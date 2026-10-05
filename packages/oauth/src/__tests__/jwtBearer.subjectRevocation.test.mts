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
	type AssertionVerificationResult,
	type AssertionVerifier,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantPolicyDecision,
	type GrantPolicyHook,
	type SubjectRevocation,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createJwtBearerGrant, JWT_BEARER_GRANT_TYPE } from "#/grants/jwtBearer.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";

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
}) =>
	createJwtBearerGrant({
		config,
		keyStore,
		assertionVerifier: verifierFor(opts.issuedAt === undefined ? {} : { issuedAt: opts.issuedAt }),
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
				"jwt_bearer_assertion_issued_at_missing",
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
			issuedAt: 1,
			subjectRevocation: revocationAt(() => new Date(Number.NaN)),
		}).handle(ctx());
		expect(result.status).toBe(503);
	});

	it("refuses an assertion that lapsed while the boundary was read", async () => {
		const now = Date.now();
		const clock = vi.spyOn(Date, "now").mockReturnValue(now);
		try {
			const grant = createJwtBearerGrant({
				config,
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
		const moduleConfig = {
			...(makeValidAppConfig() as unknown as Record<string, unknown>),
			"oauth-authorization": { grants: { jwtBearer: { enabled: true } } },
		} as never;
		const grants = (oauthAuthorizationModule({ config: moduleConfig }).contributes?.grants ??
			{}) as Record<
			string,
			(deps: unknown) => { handle(c: GrantContext): Promise<{ result: unknown }> }
		>;
		const factory = grants[JWT_BEARER_GRANT_TYPE];
		expect(factory).toBeDefined();
		const grant = factory?.({
			config: moduleConfig,
			keyStore,
			assertionVerifier: verifierFor({ issuedAt: BOUNDARY_SECOND - 60 }),
			userRepository,
			subjectRevocation: revocationAt(() => BOUNDARY),
		});
		expect((await grant?.handle(ctx()))?.result).toEqual(refused);
	});
});
