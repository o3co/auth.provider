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
 * Refresh-token issuance for the webauthn grant (#480).
 *
 * The grant used to hand back an access token alone, so a passkey-only user on
 * a native app was bounced to the platform authenticator at every access-token
 * expiry. It now opens a refresh-token family exactly the way the
 * authorization-code grant does, but only for a client whose
 * `allowedGrantTypes` names `refresh_token` — the deny-by-absence discipline of
 * #268 / #311 / #326.
 *
 * What is asserted here:
 *   - the allowlist gate, in all four of its shapes (named / omitted /
 *     undeclared / no authenticated client);
 *   - that the issued token satisfies every gate `refresh_token`'s own handler
 *     applies at redemption — `typ = rt+jwt`, pinned `iss`, `azp` equal to the
 *     issuing client, a `family_id` claim — checked through core's `verifyJwt`,
 *     the same verifier that handler calls;
 *   - that the family the grant registers rotates once and then reports a
 *     replay, driven through core's real store + rotation wrapper rather than a
 *     spy, so the RFC 6819 §5.2.2.3 semantics are the shared ones;
 *   - that no refresh token is served unless its family was registered — a
 *     store outage, a decode that throws, and a payload missing `jti` or `exp`
 *     all answer 503 and return no tokens at all;
 *   - the DPoP `cnf.jkt` binding, on the same public-client /
 *     `bindConfidentialClientRefreshTokens` gate `authorization.mts` and
 *     `refreshToken.mts` apply.
 *
 * `verifyWebAuthnAssertion` is mocked for the same reason grant.test.mts mocks
 * it: the assertion-verification contract is covered by
 * internal.verification.test.mts and real CBOR/COSE fixtures add nothing here.
 */

import {
	type ChallengeCeremony,
	type ChallengeCeremonyOutcome,
	createMemoryRefreshTokenFamilyStore,
	createMemoryWebAuthnCredentialStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type RefreshTokenFamilyRotation,
	type TokenBinding,
	verifyJwt,
	type WebAuthnCredential,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAttestation: vi.fn(),
}));

// Spied, not replaced: the default implementation is the real one, so every
// test below exercises the genuine decode. Only the unregisterable-token cases
// override it, one call at a time, to reach branches a correctly minted token
// cannot produce.
vi.mock("#/internal/_jwtPayload.mjs", async () => {
	const actual = await vi.importActual<typeof import("#/internal/_jwtPayload.mjs")>(
		"#/internal/_jwtPayload.mjs",
	);
	return { decodeJwtPayload: vi.fn(actual.decodeJwtPayload) };
});

import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { decodeJwtPayload } from "#/internal/_jwtPayload.mjs";
import { verifyWebAuthnAssertion } from "#/internal/verification.mjs";
import { webauthnModule } from "#/module.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);
const mockDecodeJwtPayload = vi.mocked(decodeJwtPayload);

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

function makeConfig(
	overrides: { readonly bindConfidentialClientRefreshTokens?: boolean } = {},
): GrantDependencies["config"] {
	return {
		oauth: {
			jwt: { issuer: ISSUER },
			accessToken: { expiresIn: ACCESS_TOKEN_TTL },
			refreshToken: { expiresIn: REFRESH_TOKEN_TTL },
			...(overrides.bindConfidentialClientRefreshTokens === undefined
				? {}
				: {
						tokenBinding: {
							bindConfidentialClientRefreshTokens: overrides.bindConfidentialClientRefreshTokens,
						},
					}),
		},
	} as unknown as GrantDependencies["config"];
}

type WebAuthnDeps = Parameters<typeof createWebAuthnGrant>[0];

async function makeDeps(
	overrides: Partial<WebAuthnDeps> & { readonly config?: GrantDependencies["config"] } = {},
): Promise<WebAuthnDeps> {
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential(makeCredential());
	return {
		config: makeConfig(),
		keyStore,
		webauthnCredentialStore: credentialStore,
		challengeCeremony: makeConsumedCeremony(),
		webauthnConfig: {
			rpId: "test.example",
			origin: [ISSUER],
			userVerification: "preferred" as const,
		},
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
// The allowlist gate (#268 / #311 / #326 deny-by-absence)
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — refresh_token allowlist gate (#480)", () => {
	it("issues a refresh_token when the client's allowedGrantTypes names refresh_token", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		expect(typeof tokens.refresh_token).toBe("string");
	});

	it("issues no refresh_token when allowedGrantTypes omits refresh_token", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ allowedGrantTypes: [WEBAUTHN_GRANT_TYPE] })),
		);

		expect(tokens.refresh_token).toBeUndefined();
		// Exactly today's response: an access token, nothing more.
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

describe("createWebAuthnGrant — the issued refresh token is redeemable (#480)", () => {
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

describe("createWebAuthnGrant — refresh-token family lifecycle (#480)", () => {
	it("registers the family under the issued token's own jti and exp", async () => {
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
	});

	it("rotates once and then reports a replay, on core's own rotation wrapper", async () => {
		// The store and the wrapper are the real ones — this is the machinery
		// refreshToken.mts drives at redemption, so "the same replay semantics as
		// the authorization-code grant" is a property of the family this grant
		// creates, not of a stub written to agree with it.
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
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
		// Fail-closed, matching authorization.mts CP-16: a refresh token whose
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

	// -------------------------------------------------------------------------
	// A token that cannot be registered must not be served either
	//
	// Registration needs the `jti` and `exp` of the token just minted. Reading
	// them back can fail — the decode can throw, or return a payload missing
	// either claim — and the first shape of this code treated that as "nothing
	// to register" and returned the refresh token anyway. That is the same
	// outcome as the store outage above (a live refresh token with no rotation
	// record and no replay detection) reached down a different branch, so it
	// gets the same fail-closed answer.
	// -------------------------------------------------------------------------

	it("answers 503 and serves nothing when the minted token cannot be decoded", async () => {
		const register = vi.fn(async () => {});
		const deps = await makeDeps({
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		});
		mockDecodeJwtPayload.mockImplementationOnce(() => {
			throw new Error("decode blew up");
		});

		const { result } = await createWebAuthnGrant(deps).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
		expect("tokens" in result).toBe(false);
		expect(register).not.toHaveBeenCalled();
	});

	it("answers 503 and serves nothing when the minted token carries no jti", async () => {
		const register = vi.fn(async () => {});
		const deps = await makeDeps({
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		});
		mockDecodeJwtPayload.mockReturnValueOnce({ exp: Math.floor(Date.now() / 1000) + 60 });

		const { result } = await createWebAuthnGrant(deps).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
		expect("tokens" in result).toBe(false);
		expect(register).not.toHaveBeenCalled();
	});

	it("answers 503 and serves nothing when the minted token carries no exp", async () => {
		const register = vi.fn(async () => {});
		const deps = await makeDeps({
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		});
		mockDecodeJwtPayload.mockReturnValueOnce({ jti: "a-jti-with-no-exp" });

		const { result } = await createWebAuthnGrant(deps).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
		expect("tokens" in result).toBe(false);
		expect(register).not.toHaveBeenCalled();
	});

	it("answers 503 when oauth.refreshToken.expiresIn is unset, so the token has no exp", async () => {
		// The same guard reached without touching the decoder: no configured TTL
		// means `generateToken` emits no `exp` claim, so the family would have no
		// expiry to register under. A misconfiguration must not degrade into an
		// unregistered refresh token.
		const noTtlConfig = {
			oauth: {
				jwt: { issuer: ISSUER },
				accessToken: { expiresIn: ACCESS_TOKEN_TTL },
				refreshToken: {},
			},
		} as unknown as GrantDependencies["config"];

		const { result } = await createWebAuthnGrant(
			await makeDeps({
				config: noTtlConfig,
				refreshTokenFamilyRotation: {
					register: vi.fn(async () => {}),
					rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
				},
			}),
		).handle(makeCtx(makeClient()));

		expect(result.status).toBe(503);
		expect("tokens" in result).toBe(false);
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

describe("createWebAuthnGrant — DPoP-bound refresh tokens (#480)", () => {
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

	it("binds a confidential client's refresh token when the deployment opts in (#275)", async () => {
		const tokens = await issue(
			await makeDeps({ config: makeConfig({ bindConfidentialClientRefreshTokens: true }) }),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
				tokenBinding: dpopBinding("PROOF-JKT"),
			}),
		);

		expect(decodePayload(tokens.refresh_token as string).cnf).toEqual({ jkt: "PROOF-JKT" });
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
// component reaches it. `webauthnModule` builds its grant deps field by field
// rather than forwarding the whole bag, so a slot it does not name is a slot
// the grant never sees — replay detection would be silently absent in every
// real deployment while every grant-level test above still passed. That is the
// same wiring class as the C1 `grantPolicy` bypass (PR #172).
// ---------------------------------------------------------------------------

describe("webauthnModule — refresh-token family wiring (#480)", () => {
	it("declares refreshTokenFamilyRotation as an optional slot", () => {
		expect(webauthnModule.optional).toContain("refreshTokenFamilyRotation");
	});

	it("forwards the wired rotation component into the grant it contributes", async () => {
		const register = vi.fn(async () => {});
		const credentialStore = createMemoryWebAuthnCredentialStore();
		await credentialStore.registerCredential(makeCredential());

		const grantFactory = webauthnModule.contributes?.grants?.[WEBAUTHN_GRANT_TYPE];
		if (!grantFactory) throw new Error("webauthnModule contributes no webauthn grant");

		const handler = grantFactory({
			config: makeConfig(),
			keyStore,
			webauthnCredentialStore: credentialStore,
			challengeCeremony: makeConsumedCeremony(),
			webauthnConfig: {
				rpId: "test.example",
				rpName: "Test",
				origin: [ISSUER],
				challengeTtlMs: 120_000,
				attestationPreference: "none",
				userVerification: "preferred",
				allowCredentialsForKnownUser: false,
				rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
			},
			grantPolicy: { kind: "test-noop", evaluate: async () => ({ outcome: "allow" }) as const },
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
		} as never);

		const { result } = await handler.handle(makeCtx(makeClient()));

		expect(result.status).toBe(200);
		expect(register).toHaveBeenCalledTimes(1);
	});
});
