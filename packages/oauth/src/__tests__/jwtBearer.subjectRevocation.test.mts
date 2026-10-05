/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The jwt-bearer grant holds the assertion's issue time to the resolved
 * subject's revocation boundary: an assertion issued at or before a subject
 * revocation (with `verifyJwt`'s allowance) is not redeemed after it.
 */

import {
	type AppConfig,
	ASSERTION_MAX_LIFETIME_LIMIT_SECONDS,
	type AssertionVerificationResult,
	type AssertionVerifier,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantPolicyDecision,
	type GrantPolicyHook,
	MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS,
	type SubjectRevocation,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createJwtBearerGrant, JWT_BEARER_GRANT_TYPE } from "#/grants/jwtBearer.mjs";
import { oauthAuthorizationGrantsModule } from "#/oauthAuthorization.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
const config = {
	oauth: { jwt: { issuer: "https://auth.example" }, accessToken: { expiresIn: 300 } },
} as unknown as AppConfig;

/** A boundary 10 minutes ago, with a sub-second part, as a store records it. */
const BOUNDARY = new Date(Math.floor(Date.now() / 1000) * 1000 - 600_000 + 300);
const BOUNDARY_SECOND = Math.floor(BOUNDARY.getTime() / 1000);

const verifierFor = (result: Partial<AssertionVerificationResult> = {}): AssertionVerifier => ({
	kind: "stub",
	verify: async () => ({ subjectHandle: "device:abc", ...result }),
});

const userRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => ({ id: "user-42" }),
} as unknown as UserRepository;

const revocationAt = (
	boundary: () => Date | null,
): Pick<SubjectRevocation, "revokedBefore"> & { readonly calls: string[] } => {
	const calls: string[] = [];
	return {
		calls,
		revokedBefore: async (subject: string) => {
			calls.push(subject);
			return boundary();
		},
	};
};

const build = (opts: {
	issuedAt?: number;
	subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
	grantPolicy?: GrantPolicyHook;
	logger?: unknown;
	userRepository?: UserRepository;
	/** The assertion's expiry; five minutes from now unless given (`null` reports none). */
	expiresAt?: number | null;
}) =>
	createJwtBearerGrant({
		...grantSettingsFrom(config),
		keyStore,
		assertionVerifier: verifierFor({
			...(opts.issuedAt === undefined ? {} : { issuedAt: opts.issuedAt }),
			...(opts.expiresAt === null
				? {}
				: { expiresAt: opts.expiresAt ?? Math.floor(Date.now() / 1000) + 300 }),
		}),
		userRepository: opts.userRepository ?? userRepository,
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
	} as never);

const ctx = (): GrantContext =>
	({
		body: { assertion: "an-assertion" },
		session: {},
		issuer: "https://auth.example",
		metadata: {},
		authenticatedClient: null,
	}) as GrantContext;

const refused = {
	status: 400,
	error: "invalid_grant",
	errorDescription: "assertion did not verify",
};

describe("jwt-bearer grant — the subject revocation boundary", () => {
	it("refuses an assertion issued before the boundary, in its second, or within the allowance after it", async () => {
		const subjectRevocation = revocationAt(() => BOUNDARY);
		for (const issuedAt of [BOUNDARY_SECOND - 60, BOUNDARY_SECOND, BOUNDARY_SECOND + 1]) {
			const { result } = await build({ issuedAt, subjectRevocation }).handle(ctx());
			expect(result).toEqual(refused);
		}
		// The boundary of the subject the Store resolved, not the handle.
		expect(subjectRevocation.calls).toEqual(["user-42", "user-42", "user-42"]);
	});

	it("accepts an assertion issued after the boundary plus the allowance", async () => {
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND + 2,
			subjectRevocation: revocationAt(() => BOUNDARY),
		}).handle(ctx());
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).sub).toBe("user-42");
	});

	it("accepts any assertion while the subject has no boundary in force", async () => {
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND - 60,
			subjectRevocation: revocationAt(() => null),
		}).handle(ctx());
		expect(result.status).toBe(200);
	});

	it("refuses an assertion without an issue time whenever subjectRevocation is wired, boundary or not, before asking the Store", async () => {
		for (const boundary of [BOUNDARY, null]) {
			const info = vi.fn();
			const authenticateByToken = vi.fn(async () => ({ id: "user-42" }));
			const subjectRevocation = revocationAt(() => boundary);
			const { result } = await build({
				subjectRevocation,
				userRepository: { authenticate: async () => null, authenticateByToken } as never,
				logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
			}).handle(ctx());
			expect(result).toEqual(refused);
			expect(info).toHaveBeenCalledWith(
				expect.objectContaining({ kind: "stub" }),
				"jwt_bearer_assertion_issued_at_unusable",
			);
			expect(authenticateByToken).not.toHaveBeenCalled();
			expect(subjectRevocation.calls).toEqual([]);
		}
	});

	it("refuses an issue time that is not a usable date whenever subjectRevocation is wired", async () => {
		for (const boundary of [BOUNDARY, null]) {
			for (const issuedAt of [Number.NaN, Number.POSITIVE_INFINITY, 1e300, "1700000000"]) {
				const { result } = await build({
					issuedAt: issuedAt as number,
					subjectRevocation: revocationAt(() => boundary),
				}).handle(ctx());
				expect(result).toEqual(refused);
			}
		}
	});

	it("logs a covered assertion as revoked", async () => {
		const info = vi.fn();
		await build({
			issuedAt: BOUNDARY_SECOND - 60,
			subjectRevocation: revocationAt(() => BOUNDARY),
			logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
		}).handle(ctx());
		expect(info).toHaveBeenCalledWith(
			expect.objectContaining({ kind: "stub" }),
			"jwt_bearer_assertion_revoked",
		);
	});

	it("answers 503 when the boundary cannot be read, and logs it", async () => {
		const error = vi.fn();
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND + 60,
			subjectRevocation: {
				revokedBefore: async () => {
					throw new Error("ECONNREFUSED");
				},
			},
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
		}).handle(ctx());
		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "revocation store unavailable",
		});
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "revocation_boundary",
				err: expect.objectContaining({ detail: "ECONNREFUSED" }),
			}),
			"jwt_bearer_revocation_boundary_unavailable",
		);
	});

	it("answers 503 when the store answers a boundary that is not a date", async () => {
		for (const boundary of ["2026-01-01", new Date(Number.NaN)]) {
			const { result } = await build({
				issuedAt: BOUNDARY_SECOND + 60,
				subjectRevocation: revocationAt(() => boundary as Date),
			}).handle(ctx());
			expect(result.status).toBe(503);
		}
	});

	it("answers 503 for a boundary that is not a valid date, even for an issue time long before it", async () => {
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND - 3600,
			subjectRevocation: revocationAt(() => new Date(Number.NaN)),
		}).handle(ctx());
		expect(result.status).toBe(503);
	});

	it("refuses an assertion that lapsed while the boundary was read", async () => {
		const now = Date.now();
		const clock = vi.spyOn(Date, "now").mockReturnValue(now);
		try {
			const grant = createJwtBearerGrant({
				...grantSettingsFrom(config),
				keyStore,
				assertionVerifier: verifierFor({
					issuedAt: BOUNDARY_SECOND + 60,
					expiresAt: Math.floor(now / 1000) + 2,
				}),
				userRepository,
				subjectRevocation: {
					revokedBefore: async () => {
						clock.mockReturnValue(now + 3_000);
						return null;
					},
				},
			} as never);
			const { result } = await grant.handle(ctx());
			expect(result).toEqual(refused);
		} finally {
			clock.mockRestore();
		}
	});

	it("answers 503 rather than sign a token whose lifetime ran out during the boundary read", async () => {
		const now = Date.now();
		const clock = vi.spyOn(Date, "now").mockReturnValue(now);
		try {
			const grant = createJwtBearerGrant({
				...grantSettingsFrom({
					oauth: {
						jwt: { issuer: "https://auth.example" },
						accessToken: { defaultExpiresIn: 5, maxExpiresIn: 5 },
					},
				}),
				keyStore,
				assertionVerifier: verifierFor({
					issuedAt: BOUNDARY_SECOND + 60,
					expiresAt: Math.floor(now / 1000) + 3600,
				}),
				userRepository,
				subjectRevocation: {
					revokedBefore: async () => {
						clock.mockReturnValue(now + 6_000);
						return null;
					},
				},
			} as never);
			const { result } = await grant.handle(ctx());
			expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		} finally {
			clock.mockRestore();
		}
	});

	describe("an assertion's lifetime, with subjectRevocation wired", () => {
		const SEVEN_DAYS = 7 * 86_400;
		const now = () => Math.floor(Date.now() / 1000);

		it("refuses a 7-day assertion from a custom verifier while a boundary is in force and after it lapses, before asking the Store", async () => {
			for (const boundary of [BOUNDARY, null]) {
				const info = vi.fn();
				const authenticateByToken = vi.fn(async () => ({ id: "user-42" }));
				const issuedAt = now() - 60;
				const { result } = await build({
					issuedAt,
					expiresAt: issuedAt + SEVEN_DAYS,
					subjectRevocation: revocationAt(() => boundary),
					userRepository: { authenticate: async () => null, authenticateByToken } as never,
					logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
				}).handle(ctx());
				expect(result).toEqual(refused);
				expect(authenticateByToken).not.toHaveBeenCalled();
				expect(info).toHaveBeenCalledWith(
					expect.objectContaining({ kind: "stub" }),
					"jwt_bearer_assertion_lifetime_exceeded",
				);
			}
		});

		it("refuses an assertion that reports no expiry", async () => {
			for (const boundary of [BOUNDARY, null]) {
				const { result } = await build({
					issuedAt: now() - 60,
					expiresAt: null,
					subjectRevocation: revocationAt(() => boundary),
				}).handle(ctx());
				expect(result).toEqual(refused);
			}
		});

		it("accepts an assertion that lives exactly the limit, and refuses one a second longer", async () => {
			const issuedAt = now() - 60;
			const at = await build({
				issuedAt,
				expiresAt: issuedAt + ASSERTION_MAX_LIFETIME_LIMIT_SECONDS,
				subjectRevocation: revocationAt(() => BOUNDARY),
			}).handle(ctx());
			expect(at.result.status).toBe(200);
			const over = await build({
				issuedAt,
				expiresAt: issuedAt + ASSERTION_MAX_LIFETIME_LIMIT_SECONDS + 1,
				subjectRevocation: revocationAt(() => BOUNDARY),
			}).handle(ctx());
			expect(over.result).toEqual(refused);
		});

		it("leaves a long-lived or expiry-less assertion alone without subjectRevocation wired", async () => {
			const issuedAt = now() - 60;
			for (const expiresAt of [issuedAt + SEVEN_DAYS, null]) {
				const { result } = await build({ issuedAt, expiresAt }).handle(ctx());
				expect(result.status).toBe(200);
			}
		});

		it("refuses an expiry that is not after the issue time", async () => {
			const issuedAt = now() - 60;
			for (const expiresAt of [issuedAt, issuedAt - 1]) {
				const info = vi.fn();
				const { result } = await build({
					issuedAt,
					expiresAt,
					subjectRevocation: revocationAt(() => null),
					logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
				}).handle(ctx());
				expect(result).toEqual(refused);
				expect(info).toHaveBeenCalledWith(
					expect.objectContaining({ kind: "stub" }),
					"jwt_bearer_assertion_lifetime_empty",
				);
			}
		});

		it("logs an expiry it cannot use, a numeric string included", async () => {
			for (const expiresAt of [null, "1790000000", Number.NaN, Number.POSITIVE_INFINITY]) {
				const info = vi.fn();
				const { result } = await build({
					issuedAt: now() - 60,
					expiresAt: expiresAt as number | null,
					subjectRevocation: revocationAt(() => null),
					logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
				}).handle(ctx());
				expect(result, String(expiresAt)).toEqual(refused);
				expect(info).toHaveBeenCalledWith(
					expect.objectContaining({ kind: "stub" }),
					"jwt_bearer_assertion_expiry_unusable",
				);
			}
		});

		it("refuses a negative issue time", async () => {
			const { result } = await build({
				issuedAt: -1,
				subjectRevocation: revocationAt(() => null),
			}).handle(ctx());
			expect(result).toEqual(refused);
		});
	});

	describe("an issue time ahead of this server's clock", () => {
		const now = () => Math.floor(Date.now() / 1000);

		it("refuses one beyond the largest verifier clock tolerance, before asking the Store", async () => {
			const info = vi.fn();
			const authenticateByToken = vi.fn(async () => ({ id: "user-42" }));
			const issuedAt = now() + MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS + 5;
			const { result } = await build({
				issuedAt,
				expiresAt: issuedAt + 300,
				subjectRevocation: revocationAt(() => null),
				userRepository: { authenticate: async () => null, authenticateByToken } as never,
				logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
			}).handle(ctx());
			expect(result).toEqual(refused);
			expect(authenticateByToken).not.toHaveBeenCalled();
			expect(info).toHaveBeenCalledWith(
				expect.objectContaining({ kind: "stub" }),
				"jwt_bearer_assertion_issued_at_ahead",
			);
		});

		it("compares one within the tolerance as issued at this grant's own instant, so a current boundary covers it", async () => {
			// A boundary stamped now; the assertion claims to be issued 200 s
			// from now. Compared as claimed it would clear the boundary.
			const boundary = new Date(Date.now());
			const issuedAt = now() + 200;
			const { result } = await build({
				issuedAt,
				expiresAt: issuedAt + 300,
				subjectRevocation: revocationAt(() => boundary),
			}).handle(ctx());
			expect(result).toEqual(refused);
			// No boundary: accepted, the claim within the tolerance stands.
			const clear = await build({
				issuedAt,
				expiresAt: issuedAt + 300,
				subjectRevocation: revocationAt(() => null),
			}).handle(ctx());
			expect(clear.result.status).toBe(200);
		});
	});

	it("compares a fractional issue time by its second: the boundary's second plus the allowance is covered, the next is not", async () => {
		const covered = await build({
			issuedAt: BOUNDARY_SECOND + 1.9,
			subjectRevocation: revocationAt(() => BOUNDARY),
		}).handle(ctx());
		expect(covered.result).toEqual(refused);
		const clear = await build({
			issuedAt: BOUNDARY_SECOND + 2.1,
			subjectRevocation: revocationAt(() => BOUNDARY),
		}).handle(ctx());
		expect(clear.result.status).toBe(200);
	});

	it("reads the boundary after the grant policy has answered", async () => {
		// A revocation stamped while the policy is evaluated is seen.
		let boundary: Date | null = null;
		const grantPolicy: GrantPolicyHook = {
			kind: "stub",
			evaluate: async () => {
				boundary = BOUNDARY;
				return { outcome: "allow" } as GrantPolicyDecision;
			},
		};
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND - 1,
			subjectRevocation: revocationAt(() => boundary),
			grantPolicy,
		}).handle(ctx());
		expect(result).toEqual(refused);
	});

	it("reads the boundary after the Store has resolved the subject", async () => {
		let boundary: Date | null = null;
		const { result } = await build({
			issuedAt: BOUNDARY_SECOND - 1,
			subjectRevocation: revocationAt(() => boundary),
			userRepository: {
				authenticate: async () => null,
				authenticateByToken: async () => {
					boundary = BOUNDARY;
					return { id: "user-42" };
				},
			} as unknown as UserRepository,
		}).handle(ctx());
		expect(result).toEqual(refused);
	});

	it("is unchanged without subjectRevocation wired", async () => {
		for (const issuedAt of [BOUNDARY_SECOND - 60, undefined]) {
			const { result } = await build(issuedAt === undefined ? {} : { issuedAt }).handle(ctx());
			expect(result.status).toBe(200);
		}
	});

	it("gets the slot through the module", async () => {
		const grants = (oauthAuthorizationGrantsModule.contributes?.grants ?? {}) as Record<
			string,
			(deps: unknown) => { handle(c: GrantContext): Promise<{ result: unknown }> } | null
		>;
		const factory = grants[JWT_BEARER_GRANT_TYPE];
		expect(factory).toBeDefined();
		const grant = factory?.({
			section: { grants: { jwtBearer: { enabled: true } } },
			oauthTokenSettings: createTestOAuthTokenSettings(),
			keyStore,
			assertionVerifier: verifierFor({
				issuedAt: BOUNDARY_SECOND - 60,
				expiresAt: Math.floor(Date.now() / 1000) + 300,
			}),
			userRepository,
			subjectRevocation: revocationAt(() => BOUNDARY),
		});
		expect((await grant?.handle(ctx()))?.result).toEqual(refused);
	});
});
