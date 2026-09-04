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
 * Access-token sender binding for the webauthn grant (#489).
 *
 * The grant's access token never carried an RFC 7800 `cnf` claim, so a client
 * registered `senderConstrained: "dpop"` that logged in with a passkey had its
 * DPoP proof verified and then received a *bearer* access token — one that
 * replays from anywhere once captured. #480 had already carried the same
 * request's confirmation into the refresh token, which is what made the
 * asymmetry visible.
 *
 * What is asserted here:
 *   - the confirmation the request already carries reaches the access token,
 *     for both binding kinds, exactly as `authorization.mts` and
 *     `clientCredentials.mts` apply it — mechanism-agnostic, ungated;
 *   - the wire-level `token_type` describes what was minted: "DPoP" for a
 *     DPoP-bound token (RFC 9449 §5), "Bearer" for an mTLS-bound one
 *     (RFC 8705 §3, where the binding travels on the TLS layer);
 *   - the access-token gate is NOT the refresh-token gate: a confidential
 *     client's AT binds while its RT stays unbound by default (#275);
 *   - an unbound request is unchanged, down to the set of response keys.
 *
 * The proofless `senderConstrained` request never reaches this handler: the
 * shared grant-dispatch gate in `packages/oauth/src/routes.mts` refuses it
 * with 401 `invalid_client` before any grant handler runs, for every
 * `grant_type` including this one. That refusal is pinned end-to-end in
 * `packages/oauth/src/__tests__/senderConstrained.integration.test.mts`; this
 * grant adds no second copy of the rule.
 *
 * `verifyWebAuthnAssertion` is mocked for the same reason grant.test.mts mocks
 * it: the assertion-verification contract is covered by
 * internal.verification.test.mts and real CBOR/COSE fixtures add nothing here.
 */

import {
	type ChallengeCeremony,
	type ChallengeCeremonyOutcome,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type TokenBinding,
	type WebAuthnCredential,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAttestation: vi.fn(),
}));

import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { verifyWebAuthnAssertion } from "#/internal/verification.mjs";

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
const PROOF_JKT = "PROOF-JKT";
const CERT_THUMBPRINT = "CERT-X5T-S256";

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

function makeConfig(): GrantDependencies["config"] {
	return {
		oauth: {
			jwt: { issuer: ISSUER },
			accessToken: { expiresIn: ACCESS_TOKEN_TTL },
			refreshToken: { expiresIn: REFRESH_TOKEN_TTL },
		},
	} as unknown as GrantDependencies["config"];
}

type WebAuthnDeps = Parameters<typeof createWebAuthnGrant>[0];

async function makeDeps(): Promise<WebAuthnDeps> {
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
): Promise<{
	access_token: string;
	token_type: string;
	refresh_token?: string | null;
	expires_in?: number;
}> {
	const { result } = await createWebAuthnGrant(deps).handle(ctx);
	if (!("tokens" in result)) {
		throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	}
	expect(result.status).toBe(200);
	return result.tokens;
}

const dpopBinding: TokenBinding = { kind: "dpop", confirmation: { jkt: PROOF_JKT } };
const mtlsBinding: TokenBinding = {
	kind: "mtls",
	confirmation: { "x5t#S256": CERT_THUMBPRINT },
};

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
// The confirmation reaches the access token
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — access-token confirmation (#489)", () => {
	it("puts the presenting key's cnf.jkt on the access token and answers token_type DPoP", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient(), { tokenBinding: dpopBinding }),
		);

		expect(decodePayload(tokens.access_token).cnf).toEqual({ jkt: PROOF_JKT });
		expect(tokens.token_type).toBe("DPoP");
	});

	it("puts the certificate thumbprint on the access token and keeps token_type Bearer", async () => {
		// RFC 8705 §3: an mTLS-bound access token is still presented as a bearer
		// token on the wire — the binding is checked against the TLS client
		// certificate, not against a proof in the Authorization header. Same
		// answer `clientCredentials.mts` and `authorization.mts` give.
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient(), { tokenBinding: mtlsBinding }),
		);

		expect(decodePayload(tokens.access_token).cnf).toEqual({ "x5t#S256": CERT_THUMBPRINT });
		expect(tokens.token_type).toBe("Bearer");
	});

	it("binds the access token in the client-less passkey-is-the-auth-event mode", async () => {
		// The confirmation is a property of the request, not of a client
		// registration, so the mode this grant exists for is not the mode that
		// silently drops it.
		const tokens = await issue(await makeDeps(), makeCtx(null, { tokenBinding: dpopBinding }));

		expect(decodePayload(tokens.access_token).cnf).toEqual({ jkt: PROOF_JKT });
		expect(tokens.token_type).toBe("DPoP");
	});

	it("binds a confidential client's access token even though its refresh token stays unbound", async () => {
		// The two gates are deliberately different, and this is the case that
		// proves the AT did not inherit the RT's. RFC 9449 §5 leaves a
		// confidential client's RT unbound because the client secret is the
		// refresh-time authenticator (#275 opts a deployment out); nothing of the
		// sort applies to the access token, which a resource server checks against
		// the proof on every call.
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "client_secret_basic" }), {
				tokenBinding: dpopBinding,
			}),
		);

		expect(decodePayload(tokens.access_token).cnf).toEqual({ jkt: PROOF_JKT });
		expect(decodePayload(tokens.refresh_token as string).cnf).toBeUndefined();
		expect(tokens.token_type).toBe("DPoP");
	});

	it("binds both tokens for a public client, leaving #480's refresh-token gate intact", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ tokenEndpointAuthMethod: "none" }), { tokenBinding: dpopBinding }),
		);

		expect(decodePayload(tokens.access_token).cnf).toEqual({ jkt: PROOF_JKT });
		expect(decodePayload(tokens.refresh_token as string).cnf).toEqual({ jkt: PROOF_JKT });
	});
});

// ---------------------------------------------------------------------------
// The unbound request is untouched
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — unbound requests are unchanged (#489)", () => {
	it("emits no cnf and the same response keys as before, for a client that demands nothing", async () => {
		const tokens = await issue(
			await makeDeps(),
			makeCtx(makeClient({ allowedGrantTypes: [WEBAUTHN_GRANT_TYPE] })),
		);

		expect(decodePayload(tokens.access_token).cnf).toBeUndefined();
		expect(tokens.token_type).toBe("Bearer");
		expect(Object.keys(tokens).sort()).toEqual(["access_token", "expires_in", "token_type"]);
		expect(tokens.expires_in).toBe(ACCESS_TOKEN_TTL);
	});

	it("emits no cnf on either token when a refresh token is issued unbound", async () => {
		const tokens = await issue(await makeDeps(), makeCtx(makeClient()));

		expect(decodePayload(tokens.access_token).cnf).toBeUndefined();
		expect(decodePayload(tokens.refresh_token as string).cnf).toBeUndefined();
		expect(tokens.token_type).toBe("Bearer");
	});
});
