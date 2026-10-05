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
 * Refresh-token issuance for the webauthn grant, so a passkey-only user on a
 * native app is not sent to the platform authenticator at every access-token
 * expiry. It opens a refresh-token family exactly the way the
 * authorization-code grant does, but only for a client whose
 * `allowedGrantTypes` names `refresh_token` (deny by absence).
 *
 * Pinned here: the allowlist gate in its four shapes; that the issued token
 * passes every gate `refresh_token`'s own handler applies at redemption,
 * through the same `verifyJwt`; that the family rotates once and then reports
 * a replay, through core's real store and rotation wrapper (RFC 6819
 * §5.2.2.3); that the family is registered under the refresh token's reserved
 * `jti` and expiry before anything is signed, so no refresh token is served
 * unless its family was registered, and a family store that cannot answer is
 * a 503 that costs no signature; the DPoP `cnf.jkt` binding, on the same
 * public-client / `bindConfidentialClientRefreshTokens` gate
 * `authorization.mts` and `refreshToken.mts` apply, the setting read from
 * core's `tokenBindingSettings` slot and never from a configuration; and the
 * `auth_time` both
 * tokens carry, never later than the challenge's issuance.
 *
 * `verifyWebAuthnAssertion` is mocked, as in grant.test.mts: its contract is
 * covered by internal.verification.test.mts, and real CBOR/COSE fixtures add
 * nothing here.
 */

import {
	type ChallengeCeremony,
	type ChallengeCeremonyOutcome,
	createApp,
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryRefreshTokenFamilyStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	defineModule,
	type GrantContext,
	type GrantHandler,
	type GrantHandlerResolver,
	type GrantPolicyHook,
	memoryChallengeStoreModule,
	type RefreshTokenFamilyRotation,
	type TokenBinding,
	verifyJwt,
	type WebAuthnCredential,
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
import { makeAppConfig, withWebAuthnSection } from "./appConfig.fixture.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);

const ISSUER = "https://test.example";
const USER_ID = "user-alice-123";
const CLIENT_ID = "native-app-client";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk"; // base64url of "test-credential-id"
const ACCESS_TOKEN_TTL = 3600;
const REFRESH_TOKEN_TTL = 86_400;

type AuthenticatedClient = NonNullable<GrantContext["authenticatedClient"]>;

function makeAssertionResponse(challenge = "test-challenge-value"): AuthenticationResponseJSON {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.get", challenge, origin: ISSUER }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: {
			clientDataJSON,
			authenticatorData: "stub-authdata",
			signature: "stub-signature",
			userHandle: Buffer.from(USER_ID, "utf8").toString("base64url"),
		},
		clientExtensionResults: {},
		type: "public-key",
	};
}

function makeCredential(): WebAuthnCredential {
	return {
		userId: USER_ID,
		credentialId: CREDENTIAL_ID,
		publicKey: new Uint8Array(64),
		signCount: 5,
		backedUp: false,
		createdAt: new Date("2026-01-01"),
	};
}

function makeConsumedCeremony(): ChallengeCeremony {
	return {
		consume: vi.fn().mockResolvedValue({ outcome: "consumed" } as ChallengeCeremonyOutcome),
	};
}

/** The slot the grant mints with: this file's issuer and lifetimes. */
const tokenSettings = () =>
	createTestOAuthTokenSettings({
		issuer: ISSUER,
		accessTokenLifetime: { defaultExpiresIn: ACCESS_TOKEN_TTL, maxExpiresIn: ACCESS_TOKEN_TTL },
		refreshTokenExpiresIn: REFRESH_TOKEN_TTL,
	});

type WebAuthnDeps = Parameters<typeof createWebAuthnGrant>[0];

/** The grant's deps: no configuration among them, the binding rule from core's slot. */
async function makeDeps(overrides: Partial<WebAuthnDeps> = {}): Promise<WebAuthnDeps> {
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential(makeCredential());
	return {
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		webauthnCredentialStore: credentialStore,
		challengeCeremony: makeConsumedCeremony(),
		oauthTokenSettings: tokenSettings(),
		webauthnConfig: createTestWebAuthnConfig({ origin: [ISSUER] }),
		...overrides,
	};
}

function makeClient(overrides: Partial<AuthenticatedClient> = {}): AuthenticatedClient {
	return {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none",
		allowedGrantTypes: [WEBAUTHN_GRANT_TYPE, "refresh_token"],
		allowedScopes: [],
		allowedAudiences: [],
		...overrides,
	};
}

function makeCtx(
	authenticatedClient: AuthenticatedClient | null,
	extra: { readonly body?: Record<string, unknown>; readonly tokenBinding?: TokenBinding } = {},
): GrantContext {
	return {
		body: {
			grant_type: WEBAUTHN_GRANT_TYPE,
			assertion: makeAssertionResponse(),
			...extra.body,
		},
		session: {},
		issuer: ISSUER,
		metadata: {},
		authenticatedClient,
		...(extra.tokenBinding ? { tokenBinding: extra.tokenBinding } : {}),
	};
}

/** Runs the grant and asserts a 200, returning the token response. */
async function issue(
	deps: WebAuthnDeps,
	ctx: GrantContext,
): Promise<{ access_token: string; refresh_token?: string | null }> {
	const { result } = await createWebAuthnGrant(deps).handle(ctx);
	if (!("tokens" in result)) {
		throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	}
	expect(result.status).toBe(200);
	return result.tokens;
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

function dpopBinding(jkt: string): TokenBinding {
	return { kind: "dpop", confirmation: { jkt } };
}

function decodePayload(token: string): Record<string, unknown> {
	const parts = token.split(".");
	if (parts.length < 2) throw new Error("invalid jwt");
	return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
}

beforeEach(() => {
	vi.clearAllMocks();
	mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });
});

// ---------------------------------------------------------------------------
// The lifetimes it mints with, read when it is built
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — the oauthTokenSettings it reads", () => {
	it("mints from the slot alone, with no configuration in its deps", async () => {
		const tokens = await issue(
			await makeDeps({
				oauthTokenSettings: createTestOAuthTokenSettings({
					issuer: ISSUER,
					accessTokenLifetime: { defaultExpiresIn: 111, maxExpiresIn: 111 },
					refreshTokenExpiresIn: 2222,
				}),
			}),
			makeCtx(makeClient()),
		);
		const access = decodePayload(tokens.access_token);
		const refresh = decodePayload(tokens.refresh_token as string);
		expect((access.exp as number) - (access.iat as number)).toBe(111);
		expect((refresh.exp as number) - (refresh.iat as number)).toBe(2222);
	});

	it("is never built without the slot, naming it", async () => {
		const { oauthTokenSettings: _slot, ...deps } = await makeDeps({
			oauthTokenSettings: createTestOAuthTokenSettings({ issuer: ISSUER }),
		});
		expect(() => createWebAuthnGrant(deps as never)).toThrow(/oauthTokenSettings/);
	});
});

describe("createWebAuthnGrant — the lifetimes it mints with", () => {
	// A slot built by hand never met boot's check. The lifetimes are read when the grant is
	// built: read per request, a bad one would be refused only after the ceremony had consumed
	// the challenge — a 500, and a passkey assertion that can never be presented again.
	const broken: Array<[string, Record<string, unknown>]> = [
		["refreshTokenExpiresIn = 1.5", { refreshTokenExpiresIn: 1.5 }],
		["refreshTokenExpiresIn = NaN", { refreshTokenExpiresIn: Number.NaN }],
		["refreshTokenExpiresIn = 0", { refreshTokenExpiresIn: 0 }],
		["no refreshTokenExpiresIn", { refreshTokenExpiresIn: undefined }],
		[
			"accessTokenLifetime.defaultExpiresIn = 1.5",
			{ accessTokenLifetime: { defaultExpiresIn: 1.5, maxExpiresIn: ACCESS_TOKEN_TTL } },
		],
	];
	for (const [label, over] of broken) {
		it(`is refused when it is built with a slot whose ${label}, and no challenge is consumed`, async () => {
			const challengeStore = createMemoryChallengeStore();
			const challengeCeremony = createChallengeCeremony({
				challengeStore,
				replaySeenSet: createMemoryReplaySeenSet(),
			});
			const challenge = "lifetime-challenge";
			await challengeStore.issue("webauthn:authentication", challenge, Date.now() + 60_000);
			const deps = await makeDeps({
				challengeCeremony,
				oauthTokenSettings: { ...tokenSettings(), ...over } as never,
			});

			let refused: unknown;
			let handler: ReturnType<typeof createWebAuthnGrant> | undefined;
			try {
				handler = createWebAuthnGrant(deps);
			} catch (err) {
				refused = err;
			}
			// Were it built, this is the request that would consume the challenge.
			await handler
				?.handle(makeCtx(makeClient(), { body: { assertion: makeAssertionResponse(challenge) } }))
				.catch(() => undefined);

			expect(await challengeStore.find("webauthn:authentication", challenge)).not.toBeNull();
			expect(refused).toBeInstanceOf(RangeError);
			expect((refused as Error).message).toMatch(
				/oauthTokenSettings\.(refreshTokenExpiresIn|accessTokenLifetime)/,
			);
		});
	}
});

// ---------------------------------------------------------------------------
// The allowlist gate (deny by absence)
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — refresh_token allowlist gate", () => {
	it("issues a refresh_token when the client's allowedGrantTypes names refresh_token", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		expect(typeof tokens.refresh_token).toBe("string");
	});

	it("stamps the passkey's amr on the refresh token, as on the access token", async () => {
		// The access token carries `amr: ["hwk"]`; the refresh grant mirrors
		// `amr` from the presented refresh token, so a refresh token without it
		// would hand the first refreshed access token no `hwk`.
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));
		expect(decodePayload(tokens.access_token as string).amr).toEqual(["hwk"]);
		expect(decodePayload(tokens.refresh_token as string).amr).toEqual(["hwk"]);
	});

	it("issues no refresh_token when allowedGrantTypes omits refresh_token", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ allowedGrantTypes: [WEBAUTHN_GRANT_TYPE] })),
		);

		expect(tokens.refresh_token).toBeUndefined();
		// An access token, nothing more.
		expect(tokens.access_token).toBeTruthy();
	});

	it("issues no refresh_token when the client declares no allowedGrantTypes at all", async () => {
		// Deny by absence. Dispatch already refuses this shape for the webauthn
		// grant (`requiresExplicitGrantAllowlist`), so the handler can only see it
		// under direct invocation — but the rule is the same one either way, and
		// absence must never be the path by which a standing credential is
		// acquired.
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ allowedGrantTypes: undefined })),
		);

		expect(tokens.refresh_token).toBeUndefined();
	});

	it("issues no refresh_token when no client is authenticated", async () => {
		// The passkey-is-the-auth-event mode has no client registration to consult,
		// and `refresh_token`'s own handler refuses an unauthenticated caller —
		// an RT minted here could never be redeemed.
		const tokens = await issue(await makeDeps(), makeCtx(null));

		expect(tokens.refresh_token).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Redemption preconditions — every gate refreshToken.mts applies
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — the auth_time it stamps", () => {
	// A signed assertion can be held until its challenge expires, so the time it
	// reaches the grant says nothing about when the user made the gesture. These
	// challenges are stored without their issuance, so `auth_time` falls back to
	// the earliest a live challenge could have been issued: one challenge lifetime
	// before the redemption. Whatever the grant spends after the challenge is
	// consumed (the ceremony's seen-set write, the verification) must not move it
	// later.
	const TTL_MS = 120_000;
	const ISSUED_AT_MS = Date.UTC(2026, 8, 30, 12, 0, 0);

	afterEach(() => {
		vi.useRealTimers();
	});

	for (const [heldMs, afterConsumeMs] of [
		[0, 0],
		[TTL_MS - 1_000, 0],
		[TTL_MS - 1_000, 5_000],
	] as const) {
		it(`is no later than the challenge's issuance, and at most one challenge lifetime before it, on both tokens: held ${heldMs / 1000}s, completed ${afterConsumeMs / 1000}s after the consume`, async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.setSystemTime(ISSUED_AT_MS);
			const challengeStore = createMemoryChallengeStore();
			const challengeCeremony = createChallengeCeremony({
				challengeStore,
				replaySeenSet: createMemoryReplaySeenSet(),
			});
			await challengeStore.issue(
				"webauthn:authentication",
				"held-challenge",
				ISSUED_AT_MS + TTL_MS,
			);
			const deps = await makeDeps({
				challengeCeremony,
				webauthnConfig: createTestWebAuthnConfig({ origin: [ISSUER], challengeTtlMs: TTL_MS }),
			});

			// The verification runs after the challenge is consumed; a slow one moves the clock.
			mockVerifyAssertion.mockImplementationOnce(async () => {
				vi.setSystemTime(Date.now() + afterConsumeMs);
				return { ok: true, newSignCount: 6 };
			});
			vi.setSystemTime(ISSUED_AT_MS + heldMs);
			const tokens = await issue(
				deps,
				makeCtx(makeClient(), { body: { assertion: makeAssertionResponse("held-challenge") } }),
			);

			const authTime = decodePayload(tokens.access_token).auth_time as number;
			expect(authTime).toBeLessThanOrEqual(Math.floor(ISSUED_AT_MS / 1000));
			expect(authTime).toBeGreaterThanOrEqual(Math.floor((ISSUED_AT_MS - TTL_MS) / 1000));
			expect(decodePayload(tokens.refresh_token as string).auth_time).toBe(authTime);
		});
	}
});

describe("createWebAuthnGrant — the issued refresh token is redeemable", () => {
	it("verifies as an rt+jwt bound to the issuing client, subject and scope", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient(), { body: { scope: "read write" } }),
		);

		const refreshToken = tokens.refresh_token;
		if (typeof refreshToken !== "string") throw new Error("expected a refresh token");

		// The same verifier, with the same options, that refreshToken.mts runs at
		// redemption: `typ` pinning plus the issuer pin.
		const verified = await verifyJwt(refreshToken, keyStore, {
			type: "refresh_token",
			expectedIssuer: ISSUER,
			expectedAzp: CLIENT_ID,
			// The token was minted a millisecond ago by this test; there is
			// nothing for a revocation store to say about it.
			revocation: "none",
		});

		expect(verified.header.typ).toBe("rt+jwt");
		expect(verified.payload.sub).toBe(USER_ID);
		expect(verified.payload.scope).toBe("read write");
		expect(typeof verified.payload.family_id).toBe("string");
		expect(typeof verified.payload.jti).toBe("string");
	});

	it("honours oauth.refreshToken.expiresIn rather than the access-token TTL", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		const payload = decodePayload(tokens.refresh_token as string);
		expect((payload.exp as number) - (payload.iat as number)).toBe(REFRESH_TOKEN_TTL);

		const accessPayload = decodePayload(tokens.access_token);
		expect((accessPayload.exp as number) - (accessPayload.iat as number)).toBe(ACCESS_TOKEN_TTL);
	});

	it("puts the same family_id on the access token so revoking the family reaches it", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		const accessFamilyId = decodePayload(tokens.access_token).family_id;
		const refreshFamilyId = decodePayload(tokens.refresh_token as string).family_id;

		expect(typeof accessFamilyId).toBe("string");
		expect(accessFamilyId).toBe(refreshFamilyId);
	});

	it("leaves the access token free of family_id when no refresh token is issued", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ allowedGrantTypes: [WEBAUTHN_GRANT_TYPE] })),
		);

		expect(decodePayload(tokens.access_token).family_id).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Family registration, rotation and replay detection
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — refresh-token family lifecycle", () => {
	it("registers the family under the minted refresh token's own jti, expiring exactly at its exp", async () => {
		const register = vi.fn(async () => {});
		const rotation: RefreshTokenFamilyRotation = {
			register,
			rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
		};

		const tokens = await issue(
			await makeDeps({ refreshTokenFamilyRotation: rotation }),
			makeCtx(makeClient()),
		);

		expect(register).toHaveBeenCalledTimes(1);
		const [jti, familyId, expiresAtMs] = register.mock.calls[0] as unknown as [
			string,
			string,
			number,
		];
		const payload = decodePayload(tokens.refresh_token as string);
		expect(jti).toBe(payload.jti);
		expect(familyId).toBe(payload.family_id);
		expect(expiresAtMs).toBe((payload.exp as number) * 1000);
		expect((payload.exp as number) - (payload.iat as number)).toBe(REFRESH_TOKEN_TTL);
	});

	it("registers the family before anything is signed, so a family store that cannot answer costs no signature", async () => {
		// The refresh token's identity — its `jti` and the instant its lifetime
		// is measured from — is reserved first and registered with the family
		// store; tokens are signed only once that holds, as the refresh grant
		// does. A KMS-backed key bills every signature.
		const signing = createSymmetricKeyStore(SECRET);
		const sign = vi.spyOn(signing, "sign");
		const register = vi.fn(async () => {
			throw new Error("family store down");
		});
		const logger = spyLogger();

		const { result } = await createWebAuthnGrant(
			await makeDeps({
				keyStore: signing,
				refreshTokenFamilyRotation: {
					register,
					rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
				},
				logger,
			}),
		).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("tokens" in result).toBe(false);
		expect(register).toHaveBeenCalledTimes(1);
		expect(sign).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error.mock.calls[0]?.[1]).toBe("webauthn_grant_store_unavailable");
	});

	it("rotates once and then reports a replay, on core's own rotation wrapper", async () => {
		// The store and the wrapper are the real ones — this is the machinery
		// refreshToken.mts drives at redemption, so "the same replay semantics as
		// the authorization-code grant" is a property of the family this grant
		// creates, not of a stub written to agree with it.
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: 3_600_000,
		});

		const tokens = await issue(
			await makeDeps({ refreshTokenFamilyRotation: rotation }),
			makeCtx(makeClient()),
		);
		const payload = decodePayload(tokens.refresh_token as string);
		const familyId = payload.family_id as string;
		const firstJti = payload.jti as string;
		const expiresAtMs = (payload.exp as number) * 1000;

		// First redemption of the issued token rotates the family.
		await expect(
			rotation.rotate(firstJti, "rotated-jti-1", familyId, expiresAtMs),
		).resolves.toMatchObject({ outcome: "rotated" });

		// Presenting the already-rotated token again is a replay, and the family
		// dies with it (RFC 6819 §5.2.2.3).
		await expect(
			rotation.rotate(firstJti, "rotated-jti-2", familyId, expiresAtMs),
		).resolves.toMatchObject({ outcome: "replayed", familyRevoked: true });

		// Every descendant is dead, including the token the replay rotated to.
		await expect(
			rotation.rotate("rotated-jti-1", "rotated-jti-3", familyId, expiresAtMs),
		).resolves.toMatchObject({ outcome: "revoked" });
	});

	it("answers 503 temporarily_unavailable when the family store cannot register", async () => {
		// Fail-closed, as authorization.mts is: a refresh token whose
		// family was never registered has no replay detection behind it, so it
		// must not be served.
		const rotation: RefreshTokenFamilyRotation = {
			register: async () => {
				throw new Error("store down");
			},
			rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
		};

		const { result } = await createWebAuthnGrant(
			await makeDeps({ refreshTokenFamilyRotation: rotation }),
		).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
		expect("tokens" in result).toBe(false);
	});

	it("is never built when the slot carries no refresh-token lifetime, so no token without exp is minted", async () => {
		// With no lifetime `generateToken` emits no `exp` and the family has no expiry to
		// register under. Read when the grant is built, a missing lifetime refuses the
		// composition before any ceremony consumes a challenge.
		const { refreshTokenExpiresIn: _unset, ...withoutLifetime } = tokenSettings();
		const register = vi.fn(async () => {});
		const deps = await makeDeps({
			oauthTokenSettings: withoutLifetime as never,
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		});

		expect(() => createWebAuthnGrant(deps)).toThrow(/oauthTokenSettings\.refreshTokenExpiresIn/);
		expect(register).not.toHaveBeenCalled();
	});

	it("still issues when no rotation component is wired", async () => {
		// Same graceful degradation the authorization-code grant allows: without a
		// family store there is nothing to register, and the grant does not refuse.
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		expect(typeof tokens.refresh_token).toBe("string");
	});
});

// ---------------------------------------------------------------------------
// DPoP binding
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — DPoP-bound refresh tokens", () => {
	it("binds the refresh token to the proof key for a public client", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "none" }), {
				tokenBinding: dpopBinding("PROOF-JKT"),
			}),
		);

		expect(decodePayload(tokens.refresh_token as string).cnf).toEqual({ jkt: "PROOF-JKT" });
	});

	it("leaves a confidential client's refresh token unbound by default", async () => {
		// RFC 9449 §5: the client secret is the refresh-time authenticator, so the
		// RT is not key-bound. Same default as the other grants.
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
				tokenBinding: dpopBinding("PROOF-JKT"),
			}),
		);

		expect(decodePayload(tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("binds a confidential client's refresh token when the deployment opts in", async () => {
		const tokens = await issue(
			await makeDeps({
				tokenBindingSettings: createTestTokenBindingSettings({
					bindConfidentialClientRefreshTokens: true,
				}),
			}),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
				tokenBinding: dpopBinding("PROOF-JKT"),
			}),
		);

		expect(decodePayload(tokens.refresh_token as string).cnf).toEqual({ jkt: "PROOF-JKT" });
	});

	it.each([true, false])(
		"binds a confidential client's refresh token exactly when the tokenBindingSettings slot says %s, with no configuration in its deps",
		async (bindConfidentialClientRefreshTokens) => {
			// The setting applies across every binding mechanism, so it is core's: core fills the
			// slot from `core.tokenBinding`, and the grant reads the slot.
			const deps = await makeDeps({
				tokenBindingSettings: createTestTokenBindingSettings({
					bindConfidentialClientRefreshTokens,
				}),
			});
			expect(deps).not.toHaveProperty("config");

			const tokens = await issue(
				deps,
				makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
					tokenBinding: dpopBinding("PROOF-JKT"),
				}),
			);

			const bound = decodePayload(tokens.refresh_token as string).cnf !== undefined;
			expect(bound).toBe(bindConfidentialClientRefreshTokens);
		},
	);

	it.each([true, false])(
		"reads the slot's %s, not a configuration handed beside it that says the opposite",
		async (bindConfidentialClientRefreshTokens) => {
			// A grant that fell back to `core.tokenBinding` would read the opposite and bind
			// (or leave unbound) the other way.
			const deps = {
				...(await makeDeps({
					tokenBindingSettings: createTestTokenBindingSettings({
						bindConfidentialClientRefreshTokens,
					}),
				})),
				config: {
					core: {
						tokenBinding: {
							bindConfidentialClientRefreshTokens: !bindConfidentialClientRefreshTokens,
						},
					},
				},
			} as WebAuthnDeps;

			const tokens = await issue(
				deps,
				makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
					tokenBinding: dpopBinding("PROOF-JKT"),
				}),
			);

			const bound = decodePayload(tokens.refresh_token as string).cnf !== undefined;
			expect(bound).toBe(bindConfidentialClientRefreshTokens);
		},
	);

	it("is never built without the tokenBindingSettings slot, naming it", async () => {
		const { tokenBindingSettings: _slot, ...deps } = await makeDeps();
		expect(() => createWebAuthnGrant(deps as never)).toThrow(/tokenBindingSettings/);
	});

	it.each([
		["null", null],
		["an empty object", {}],
		[
			"a non-boolean rule",
			{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: "true" },
		],
	])("is never built with %s in the tokenBindingSettings slot, naming it", async (_label, slot) => {
		const deps = { ...(await makeDeps()), tokenBindingSettings: slot };
		expect(() => createWebAuthnGrant(deps as never)).toThrow(/tokenBindingSettings/);
	});

	it("emits no cnf when the request carried no binding", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		expect(decodePayload(tokens.refresh_token as string).cnf).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Module wiring
//
// The grant can only register a family if the composition root's rotation
// component reaches it. `webauthnModule` hands the grant its deps whole; this
// pins the end result, since a slot lost on the way would leave replay
// detection silently absent in every real deployment while every grant-level
// test above still passed.
// ---------------------------------------------------------------------------

describe("webauthnModule — refresh-token family wiring", () => {
	it("declares refreshTokenFamilyRotation as an optional slot", () => {
		expect(webauthnModule.optional).toContain("refreshTokenFamilyRotation");
	});

	it("forwards the wired rotation component into the grant it contributes", async () => {
		const register = vi.fn(async () => {});
		const credentialStore = createMemoryWebAuthnCredentialStore();
		await credentialStore.registerCredential(makeCredential());

		const grantFactory = webauthnModule.contributes?.grants?.[WEBAUTHN_GRANT_TYPE];
		if (!grantFactory) throw new Error("webauthnModule contributes no webauthn grant");

		// Awaited, as the boot planner does: a contribution factory may answer
		// with a promise.
		const handler = await grantFactory({
			tokenBindingSettings: createTestTokenBindingSettings(),
			keyStore,
			webauthnCredentialStore: credentialStore,
			challengeCeremony: makeConsumedCeremony(),
			oauthTokenSettings: tokenSettings(),
			section: {
				rpId: "test.example",
				rpName: "Test",
				origin: [ISSUER],
				challengeTtlMs: 120_000,
				attestationPreference: "none",
				userVerification: "preferred",
			},
			grantPolicy: { kind: "test-noop", evaluate: async () => ({ outcome: "allow" }) as const },
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		} as never);

		if (handler === null) throw new Error("webauthnModule's grant factory answered null");
		const { result } = await handler.handle(makeCtx(makeClient()));

		expect(result.status).toBe(200);
		expect(register).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// The binding rule, from core's slot
//
// Core fills `tokenBindingSettings` from `core.tokenBinding` in every
// composition; the module requires the slot and not the configuration, so
// the grant `createApp` registers reads the rule from what core filled.
// ---------------------------------------------------------------------------

describe("webauthnModule — the tokenBindingSettings slot", () => {
	it("requires tokenBindingSettings, and neither requires nor lists config", () => {
		expect(webauthnModule.requires).toContain("tokenBindingSettings");
		expect(webauthnModule.requires).not.toContain("config");
		expect(webauthnModule.optional).not.toContain("config");
	});

	it.each([true, false])(
		"hands the grant the slot core fills from core.tokenBinding: a confidential client's refresh token is bound exactly when it says %s",
		async (bindConfidentialClientRefreshTokens) => {
			const credentialStore = createMemoryWebAuthnCredentialStore();
			await credentialStore.registerCredential(makeCredential());
			const base = makeAppConfig();
			const handle = await createApp({
				modules: [
					webauthnModule,
					memoryChallengeStoreModule,
					defineModule({
						name: "test:webauthn-token-binding-slots",
						provides: {
							webauthnCredentialStore: () => credentialStore,
							challengeCeremony: () => makeConsumedCeremony(),
							keyStore: () => keyStore,
							grantPolicy: (): GrantPolicyHook => ({
								kind: "test-allow",
								evaluate: async () => ({ outcome: "allow" }) as const,
							}),
						},
					}),
					// Makes the planner materialise the grant registry into the handle.
					defineModule({
						name: "test:webauthn-token-binding-activator",
						requires: ["grantHandlerResolver"] as never,
					}),
				],
				bootstrapComponents: {
					config: withWebAuthnSection(
						{
							...base,
							core: {
								...base.core,
								deployment: { mode: "single" },
								tokenBinding: {
									dispatchPolicy: "intent-explicit",
									bindConfidentialClientRefreshTokens,
								},
							},
						},
						createTestWebAuthnConfig({ origin: [ISSUER] }),
					),
					pathResolver: (p: string) => p,
					oauthTokenSettings: tokenSettings(),
				} as never,
			});
			try {
				const grant = (
					(handle.components as Record<string, unknown>).grantHandlerResolver as
						| GrantHandlerResolver
						| undefined
				)?.get(WEBAUTHN_GRANT_TYPE) as GrantHandler | undefined;
				if (!grant) throw new Error("webauthnModule registered no grant");

				const { result } = await grant.handle(
					makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
						tokenBinding: dpopBinding("PROOF-JKT"),
					}),
				);
				if (!("tokens" in result))
					throw new Error(`expected tokens, got ${JSON.stringify(result)}`);

				const bound = decodePayload(result.tokens.refresh_token as string).cnf !== undefined;
				expect(bound).toBe(bindConfidentialClientRefreshTokens);
			} finally {
				await handle.dispose();
			}
		},
	);
});
