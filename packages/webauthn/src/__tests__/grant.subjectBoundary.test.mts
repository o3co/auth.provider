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
 * The webauthn grant against the subject's revocation boundary.
 *
 * Pinned here: `auth_time` is the challenge's recorded issuance, capped at the
 * redemption, and one challenge lifetime before the redemption for a challenge
 * recorded without one, whatever expiry the ceremony reports; the boundary is
 * read after every slow step
 * and before anything is registered or signed, and compared by the rule
 * `verifyJwt` applies, so a passkey authentication made before a revocation
 * mints nothing; both tokens carry one `iat`, fixed before that read, so a
 * revocation stamped later covers them; a boundary that cannot be read or
 * compared is a 503; and a grant without `subjectRevocation` mints as before.
 *
 * `verifyWebAuthnAssertion` is mocked, as in grant.test.mts: its contract is
 * covered by internal.verification.test.mts.
 */

import {
	type ChallengeCeremony,
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryRefreshTokenFamilyStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantHandler,
	type SubjectRevocation,
	verifyJwt,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
} from "@o3co/auth-provider-core/testing";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAttestation: vi.fn(),
}));

import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { verifyWebAuthnAssertion } from "#/internal/verification.mjs";
import { webauthnModule } from "#/module.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);

const ISSUER = "https://test.example";
const USER_ID = "user-alice-123";
const CLIENT_ID = "native-app-client";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk";
const CHALLENGE = "boundary-challenge";
const SCOPE = "webauthn:authentication";
const TTL_MS = 120_000;
/** A whole second, so second arithmetic in the assertions reads plainly. */
const T0 = Date.UTC(2026, 9, 5, 12, 0, 0);

const seconds = (ms: number): number => Math.floor(ms / 1000);

function assertion(): AuthenticationResponseJSON {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.get", challenge: CHALLENGE, origin: ISSUER }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: {
			clientDataJSON,
			authenticatorData: "stub",
			signature: "stub",
			userHandle: Buffer.from(USER_ID, "utf8").toString("base64url"),
		},
		clientExtensionResults: {},
		type: "public-key",
	};
}

function ctx(): GrantContext {
	return {
		body: { grant_type: WEBAUTHN_GRANT_TYPE, assertion: assertion() },
		session: {},
		issuer: ISSUER,
		metadata: {},
		authenticatedClient: {
			clientId: CLIENT_ID,
			tokenEndpointAuthMethod: "none",
			allowedGrantTypes: [WEBAUTHN_GRANT_TYPE, "refresh_token"],
			allowedScopes: [],
			allowedAudiences: [],
		},
	};
}

function decodePayload(token: string): Record<string, unknown> {
	const parts = token.split(".");
	if (parts.length < 2) throw new Error("invalid jwt");
	return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
}

/** A logger whose every level is a spy; `child` answers the same logger. */
function spyLogger() {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	return logger;
}

/** What a test arranges: when the challenge was issued, the boundary, and the slow steps. */
interface Arrangement {
	/** When the options route issued the challenge; its expiry is one lifetime later. */
	readonly challengeIssuedAtMs: number;
	/** When the assertion reaches the grant. */
	readonly redeemedAtMs: number;
	/** The boundary `revokedBefore` answers when first read; `null` is none in force. */
	readonly boundary?: Date | null;
	/** Stands in for `revokedBefore`; wins over `boundary`. */
	readonly revokedBefore?: SubjectRevocation["revokedBefore"];
	/** No `subjectRevocation` in the deps. */
	readonly withoutSubjectRevocation?: boolean;
	/** Replaces the default ceremony over the memory challenge store. */
	readonly ceremony?: ChallengeCeremony;
	/** The challenge is stored with its issuance, as the options route stores it. */
	readonly recordIssuance?: boolean;
	/** The grant's `challengeTtlMs`, when it differs from the one the challenge was issued under. */
	readonly grantChallengeTtlMs?: number;
	/** Runs inside the named step, before it answers, with the boundary's state. */
	readonly during?: Partial<
		Record<"signCount" | "policy" | "register", (state: BoundaryState) => void>
	>;
}

/** The boundary `revokedBefore` answers, which a step may stamp. */
interface BoundaryState {
	boundary: Date | null;
}

/** Stamps the boundary at the current instant: a revocation of the subject, now. */
function stampNow(state: BoundaryState): void {
	state.boundary = new Date(Date.now());
}

async function arrange(a: Arrangement) {
	vi.setSystemTime(a.challengeIssuedAtMs);
	const challengeStore = createMemoryChallengeStore();
	await challengeStore.issue(
		SCOPE,
		CHALLENGE,
		a.challengeIssuedAtMs + TTL_MS,
		...(a.recordIssuance ? [a.challengeIssuedAtMs] : []),
	);
	const ceremony =
		a.ceremony ??
		createChallengeCeremony({ challengeStore, replaySeenSet: createMemoryReplaySeenSet() });

	const state: BoundaryState = { boundary: a.boundary ?? null };
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential({
		userId: USER_ID,
		credentialId: CREDENTIAL_ID,
		publicKey: new Uint8Array(64),
		signCount: 5,
		backedUp: false,
		createdAt: new Date("2026-01-01"),
	});
	const updateSignCount = credentialStore.updateSignCount.bind(credentialStore);

	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
		accessTokenHorizonMs: 3_600_000,
	});
	const register = vi.fn(async (...args: Parameters<typeof rotation.register>) => {
		a.during?.register?.(state);
		return rotation.register(...args);
	});

	const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
	const sign = vi.spyOn(keyStore, "sign");

	const subjectRevocation: SubjectRevocation = {
		kind: "test",
		revokeBefore: vi.fn(),
		revokedBefore: vi.fn(a.revokedBefore ?? (async () => state.boundary)),
	};

	const logger = spyLogger();
	const grant = createWebAuthnGrant({
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		webauthnCredentialStore: {
			...credentialStore,
			updateSignCount: async (...args) => {
				a.during?.signCount?.(state);
				return updateSignCount(...args);
			},
		},
		challengeCeremony: ceremony,
		oauthTokenSettings: createTestOAuthTokenSettings({ issuer: ISSUER }),
		webauthnConfig: createTestWebAuthnConfig({
			origin: [ISSUER],
			challengeTtlMs: a.grantChallengeTtlMs ?? TTL_MS,
		}),
		grantPolicy: {
			kind: "test-allow",
			evaluate: async () => {
				a.during?.policy?.(state);
				return { outcome: "allow" } as const;
			},
		},
		refreshTokenFamilyRotation: { ...rotation, register },
		logger,
		...(a.withoutSubjectRevocation ? {} : { subjectRevocation }),
	});

	return {
		state,
		register,
		sign,
		subjectRevocation,
		keyStore,
		logger,
		run: async () => {
			vi.setSystemTime(a.redeemedAtMs);
			return (await grant.handle(ctx())).result;
		},
	};
}

/** Verifies a token as the refresh grant and introspection do, against `subjectRevocation`. */
function verifyAgainstBoundary(
	token: string,
	type: "access_token" | "refresh_token",
	keyStore: Parameters<typeof verifyJwt>[1],
	subjectRevocation: SubjectRevocation,
) {
	return verifyJwt(token, keyStore, {
		type,
		expectedIssuer: ISSUER,
		...(type === "access_token" ? { expectedAudience: CLIENT_ID } : { expectedAzp: CLIENT_ID }),
		revocation: { subjectRevocation },
	});
}

function tokensOf(result: Awaited<ReturnType<GrantHandler["handle"]>>["result"]) {
	if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	const refresh = result.tokens.refresh_token;
	if (typeof refresh !== "string") throw new Error("expected a refresh token");
	return { access: result.tokens.access_token, refresh };
}

beforeEach(() => {
	vi.clearAllMocks();
	vi.useFakeTimers({ toFake: ["Date"] });
	mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });
});

afterEach(() => {
	vi.useRealTimers();
});

describe("createWebAuthnGrant — the auth_time it stamps", () => {
	for (const [label, expiresAtMs] of [
		["reports no expiry", undefined],
		["reports an expiry that is not a number", Number.NaN],
		["reports the issued expiry", T0 + TTL_MS],
		["reports an expiry later than the issued one", T0 + TTL_MS + 20_000],
	] as const) {
		it(`is one challenge lifetime before the redemption when the ceremony ${label}`, async () => {
			const h = await arrange({
				challengeIssuedAtMs: T0,
				redeemedAtMs: T0 + 30_000,
				ceremony: {
					consume: async () =>
						expiresAtMs === undefined
							? { outcome: "consumed" }
							: { outcome: "consumed", expiresAtMs },
				},
			});

			const { access, refresh } = tokensOf(await h.run());

			expect(decodePayload(access).auth_time).toBe(seconds(T0 + 30_000 - TTL_MS));
			expect(decodePayload(refresh).auth_time).toBe(seconds(T0 + 30_000 - TTL_MS));
		});
	}
});

describe("createWebAuthnGrant — auth_time from the challenge's recorded issuance", () => {
	it("is the challenge's issuance when the ceremony reports it", async () => {
		const issued = T0 + 400;
		const h = await arrange({
			challengeIssuedAtMs: issued,
			redeemedAtMs: issued + 30_000,
			recordIssuance: true,
		});

		const { access, refresh } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(issued));
		expect(decodePayload(refresh).auth_time).toBe(seconds(issued));
	});

	it("is the issuance even when the grant's challenge lifetime is now shorter than the one the challenge was issued under", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 90_000,
			recordIssuance: true,
			grantChallengeTtlMs: 60_000,
		});

		const { access } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(T0));
	});

	it("is one challenge lifetime before the redemption when the challenge carries no issuance", async () => {
		const h = await arrange({ challengeIssuedAtMs: T0, redeemedAtMs: T0 + 30_000 });

		const { access } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(T0 + 30_000 - TTL_MS));
	});

	it("is the redemption when the reported issuance is later than it", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 5_000,
			ceremony: {
				consume: async () => ({
					outcome: "consumed",
					expiresAtMs: T0 + TTL_MS,
					issuedAtMs: T0 + 20_000,
				}),
			},
		});

		const { access } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(T0 + 5_000));
	});

	it("refuses a challenge issued just before a revocation of the subject", async () => {
		const stamp = T0 + 500;
		const h = await arrange({
			challengeIssuedAtMs: stamp - 1,
			redeemedAtMs: stamp + 30_000,
			boundary: new Date(stamp),
			recordIssuance: true,
		});

		expect(await h.run()).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(h.sign).not.toHaveBeenCalled();
	});

	it("mints for a challenge issued just past the revocation's allowance, though redeemed within one challenge lifetime of it", async () => {
		// Past the boundary's second plus the one-second skew `verifyJwt` allows.
		const stamp = T0 + 500;
		const issued = stamp + 2_100;
		const h = await arrange({
			challengeIssuedAtMs: issued,
			redeemedAtMs: issued + 30_000,
			boundary: new Date(stamp),
			recordIssuance: true,
		});

		const { access, refresh } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(issued));
		await expect(
			verifyAgainstBoundary(access, "access_token", h.keyStore, h.subjectRevocation),
		).resolves.toBeDefined();
		await expect(
			verifyAgainstBoundary(refresh, "refresh_token", h.keyStore, h.subjectRevocation),
		).resolves.toBeDefined();
	});
});

describe("createWebAuthnGrant — one issuance instant for both tokens", () => {
	it("signs the access and refresh token with one iat, at or after auth_time, however long the family takes to register", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 1_000,
			during: { register: () => vi.setSystemTime(Date.now() + 3_000) },
		});

		const { access, refresh } = tokensOf(await h.run());

		const at = decodePayload(access);
		const rt = decodePayload(refresh);
		expect(at.iat).toBe(rt.iat);
		expect(at.iat as number).toBeGreaterThanOrEqual(at.auth_time as number);
	});
});

describe("createWebAuthnGrant — the subject's revocation boundary", () => {
	for (const step of ["signCount", "policy"] as const) {
		it(`refuses, with nothing registered or signed, when the subject is revoked during the ${step === "policy" ? "grant policy" : "sign-count update"}`, async () => {
			const h = await arrange({
				challengeIssuedAtMs: T0,
				redeemedAtMs: T0 + 1_000,
				during: {
					[step]: (state: BoundaryState) => {
						stampNow(state);
						vi.setSystemTime(Date.now() + 5_000);
					},
				},
			});

			const result = await h.run();

			expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
			expect(h.register).not.toHaveBeenCalled();
			expect(h.sign).not.toHaveBeenCalled();
		});
	}

	it("signs tokens a revocation stamped during the family registration covers, so verifyJwt refuses both", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 1_000,
			during: {
				register: (state) => {
					stampNow(state);
					vi.setSystemTime(Date.now() + 3_000);
				},
			},
		});

		const { access, refresh } = tokensOf(await h.run());

		const boundary = h.state.boundary;
		if (boundary === null) throw new Error("the revocation was not stamped");
		expect(decodePayload(access).iat as number).toBeLessThanOrEqual(seconds(boundary.getTime()));
		expect(decodePayload(refresh).iat as number).toBeLessThanOrEqual(seconds(boundary.getTime()));
		await expect(
			verifyAgainstBoundary(access, "access_token", h.keyStore, h.subjectRevocation),
		).rejects.toMatchObject({ reason: "revoked" });
		await expect(
			verifyAgainstBoundary(refresh, "refresh_token", h.keyStore, h.subjectRevocation),
		).rejects.toMatchObject({ reason: "revoked" });
	});

	it("refuses a challenge issued before the revocation and redeemed after it", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 30_000,
			boundary: new Date(T0 + 10_000),
		});

		const result = await h.run();

		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(h.register).not.toHaveBeenCalled();
		expect(h.sign).not.toHaveBeenCalled();
		expect(h.subjectRevocation.revokedBefore).toHaveBeenCalledWith(USER_ID);
	});

	it("refuses a re-login within one challenge lifetime after the revocation, though its challenge postdates it", async () => {
		// The known cost of an auth_time one challenge lifetime early.
		const stamp = T0;
		const h = await arrange({
			challengeIssuedAtMs: stamp + 5_000,
			redeemedAtMs: stamp + 10_000,
			boundary: new Date(stamp),
		});

		expect(await h.run()).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(h.sign).not.toHaveBeenCalled();
	});

	it("mints once one challenge lifetime before the redemption is more than two seconds after the revocation, and verifyJwt accepts both tokens", async () => {
		const stamp = T0 + 500;
		const issued = stamp + 60_000;
		const redeemed = stamp + TTL_MS + 2_100;
		const h = await arrange({
			challengeIssuedAtMs: issued,
			redeemedAtMs: redeemed,
			boundary: new Date(stamp),
		});

		const { access, refresh } = tokensOf(await h.run());

		expect(decodePayload(access).auth_time).toBe(seconds(redeemed - TTL_MS));
		await expect(
			verifyAgainstBoundary(access, "access_token", h.keyStore, h.subjectRevocation),
		).resolves.toBeDefined();
		await expect(
			verifyAgainstBoundary(refresh, "refresh_token", h.keyStore, h.subjectRevocation),
		).resolves.toBeDefined();
	});

	it("mints when no boundary is in force", async () => {
		const h = await arrange({ challengeIssuedAtMs: T0, redeemedAtMs: T0 + 1_000, boundary: null });

		const result = await h.run();

		expect(result.status).toBe(200);
		expect(h.subjectRevocation.revokedBefore).toHaveBeenCalledTimes(1);
	});

	for (const [label, revokedBefore] of [
		[
			"throws",
			async () => {
				throw new Error("the boundary store is down");
			},
		],
		["answers an invalid date", async () => new Date(Number.NaN)],
		["answers something that is not a date", async () => "2026-10-05" as unknown as Date],
	] as const) {
		it(`answers 503, with nothing registered or signed, when the boundary read ${label}`, async () => {
			const h = await arrange({ challengeIssuedAtMs: T0, redeemedAtMs: T0 + 1_000, revokedBefore });

			const result = await h.run();

			expect(result).toEqual({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "revocation boundary unavailable",
			});
			expect(h.register).not.toHaveBeenCalled();
			expect(h.sign).not.toHaveBeenCalled();
			expect(h.logger.error).toHaveBeenCalledTimes(1);
			const [fields, event] = h.logger.error.mock.calls[0] as [Record<string, unknown>, string];
			expect(event).toBe("webauthn_grant_store_unavailable");
			expect(fields).toMatchObject({
				store: "revocation_boundary",
				step: "read",
				clientId: CLIENT_ID,
			});
			expect(fields.err).not.toBeInstanceOf(Error);
		});
	}

	it("mints as before, reading no boundary, without subjectRevocation", async () => {
		const h = await arrange({
			challengeIssuedAtMs: T0,
			redeemedAtMs: T0 + 30_000,
			boundary: new Date(T0 + 10_000),
			withoutSubjectRevocation: true,
		});

		const { access, refresh } = tokensOf(await h.run());

		expect(h.subjectRevocation.revokedBefore).not.toHaveBeenCalled();
		expect(decodePayload(access).auth_time).toBe(seconds(T0 + 30_000 - TTL_MS));
		expect(decodePayload(refresh).iat).toBe(decodePayload(access).iat);
	});
});

describe("webauthnModule — the subjectRevocation slot", () => {
	it("declares it optional, with no absence policy, and hands it to the grant", async () => {
		expect(webauthnModule.optional).toContain("subjectRevocation");
		expect(webauthnModule.requires).not.toContain("subjectRevocation");
		expect(Object.keys(webauthnModule.absencePolicies ?? {})).not.toContain("subjectRevocation");

		vi.setSystemTime(T0);
		const challengeStore = createMemoryChallengeStore();
		await challengeStore.issue(SCOPE, CHALLENGE, T0 + TTL_MS);
		const credentialStore = createMemoryWebAuthnCredentialStore();
		await credentialStore.registerCredential({
			userId: USER_ID,
			credentialId: CREDENTIAL_ID,
			publicKey: new Uint8Array(64),
			signCount: 5,
			backedUp: false,
			createdAt: new Date("2026-01-01"),
		});
		const factory = webauthnModule.contributes?.grants?.[WEBAUTHN_GRANT_TYPE];
		if (!factory) throw new Error("webauthnModule contributes no webauthn grant");
		const grant = (await factory({
			tokenBindingSettings: createTestTokenBindingSettings(),
			oauthTokenSettings: createTestOAuthTokenSettings({ issuer: ISSUER }),
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			webauthnCredentialStore: credentialStore,
			challengeCeremony: createChallengeCeremony({
				challengeStore,
				replaySeenSet: createMemoryReplaySeenSet(),
			}),
			section: createTestWebAuthnConfig({ origin: [ISSUER], challengeTtlMs: TTL_MS }),
			grantPolicy: { kind: "test-allow", evaluate: async () => ({ outcome: "allow" }) as const },
			subjectRevocation: {
				kind: "test",
				revokeBefore: vi.fn(),
				revokedBefore: async () => new Date(T0 + 10_000),
			},
		} as never)) as GrantHandler;

		vi.setSystemTime(T0 + 30_000);
		const { result } = await grant.handle(ctx());

		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});
});
