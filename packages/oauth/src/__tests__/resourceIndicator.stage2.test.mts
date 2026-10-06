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
 * RFC 8707 resource → audience binding enforcement (see ADR
 * 2026-07-31-rfc8707-resource-audience-binding): with the flag on and
 * `resource` present, every requested resource must be represented by the
 * token's `aud`, or the response is `400 invalid_target`. `aud` is
 * single-valued, so two distinct resources are unsatisfiable by construction.
 *
 * Enforcement is gated on the flag ALONE: with no policy wired an audience is
 * still derived (`client.allowedAudiences[0] ?? issuer`), and issuing it for
 * a mismatched `resource` would violate RFC 8707 §2.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuthenticatedClient,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantError,
	type GrantPolicyHook,
	type GrantResult,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { type AuthorizationGrantDeps, createAuthorizationGrant } from "#/grants/authorization.mjs";
import {
	type ClientCredentialsGrantDeps,
	createClientCredentialsGrant,
} from "#/grants/clientCredentials.mjs";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const CLIENT_ID = "client1";
const RP_URI = "https://rp.example/cb";
const API = "https://api.example";
const OTHER = "https://other.example";

const CC_CLIENT: AuthenticatedClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedGrantTypes: ["client_credentials"],
	allowedScopes: ["read:res"],
	// An omitted scope is granted these, never the allowlist.
	defaultScopes: ["read:res"],
	allowedAudiences: [API, OTHER],
};

const makePolicy = (evaluate: GrantPolicyHook["evaluate"]): GrantPolicyHook => ({
	kind: "stub",
	evaluate,
});

/** The result as a refusal; a result that issued tokens fails the test. */
const refusalOf = (result: GrantResult): GrantError =>
	"error" in result ? result : expect.fail(`expected a refusal, got ${result.status} with tokens`);

// ----- client_credentials -----

function makeCCDeps(
	extra: Partial<GrantDependencies> = {},
	enabled = true,
): ClientCredentialsGrantDeps {
	return {
		...grantSettingsFrom({
			oauth: {
				jwt: { issuer: "https://test.example" },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				resourceIndicator: { enabled },
			},
		}),
		keyStore,
		...extra,
	};
}

const makeCCCtx = (body: Record<string, unknown> = {}): GrantContext => ({
	body: { grant_type: "client_credentials", ...body },
	session: {},
	issuer: "https://test.example",
	metadata: {},
	authenticatedClient: CC_CLIENT,
});

// ----- refresh_token -----

const makeRefreshToken = async (): Promise<string> =>
	new SignJWT({ sub: "u1", scope: "read write" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(secretKey);

function makeRefreshDeps(
	extra: Partial<GrantDependencies> = {},
	enabled = true,
): RefreshTokenGrantDeps {
	return {
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		oauthTokenSettings: createTestOAuthTokenSettings({ resourceIndicatorEnabled: enabled }),
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		...extra,
	};
}

const makeRefreshCtx = (
	refreshToken: string,
	body: Record<string, unknown> = {},
): GrantContext => ({
	body: { grant_type: "refresh_token", refresh_token: refreshToken, ...body },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedGrantTypes: ["refresh_token"],
		allowedScopes: ["read", "write"],
		// An omitted scope is granted these, never the allowlist.
		defaultScopes: ["read", "write"],
		allowedAudiences: [API, OTHER],
	},
});

// ----- authorization_code -----

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

function makeAuthzDeps(
	grantedAudience: readonly string[] | undefined,
	enabled = true,
): AuthorizationGrantDeps {
	return {
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		...grantSettingsFrom({
			oauth: {
				jwt: { secret: "test-secret" },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {
					authorization_code: { enabled: true },
					refresh_token: { enabled: true },
				},
				resourceIndicator: { enabled },
			},
		}),
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository: {
			consumeByCode: vi.fn().mockResolvedValue({
				client_id: CLIENT_ID,
				redirect_uri: RP_URI,
				// A redeemable code always carries an S256 challenge.
				code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				code_challenge_method: "S256",
				...(grantedAudience !== undefined && { grantedAudience }),
			}),
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: mockClientRepository,
	};
}

const makeAuthzCtx = (body: Record<string, unknown> = {}): GrantContext => ({
	body: {
		code: "abc",
		redirect_uri: RP_URI,
		code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		...body,
	},
	session: { user: { id: "u1" } },
	issuer: "localhost",
	metadata: { ip: "127.0.0.1" },
	authenticatedClient: {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedGrantTypes: ["authorization_code"],
		allowedScopes: ["read:res"],
		// An omitted scope is granted these, never the allowlist.
		defaultScopes: ["read:res"],
		allowedAudiences: [API, OTHER],
	},
});

// ---------------------------------------------------------------------------
// client_credentials
// ---------------------------------------------------------------------------

describe("RFC 8707 resource → audience binding — client_credentials", () => {
	it("derives the audience from an allowed resource when no policy narrows one", async () => {
		// Without derivation the audience would fall back to
		// allowedAudiences[0] = API and a request for OTHER would reject,
		// making RFC 8707 unusable unless a policy hook is wired.
		const grant = createClientCredentialsGrant(makeCCDeps());
		const out = await grant.handle(makeCCCtx({ resource: OTHER }));

		expect(out.result.status).toBe(200);
		if (!("tokens" in out.result)) throw new Error("expected tokens");
		expect(decodeJwt(out.result.tokens.access_token).aud).toBe(OTHER);
	});

	it("rejects invalid_target for a resource the client is not allowed", async () => {
		// Derivation is bounded by allowedAudiences ∪ {clientId} — naming a
		// resource must not be enough to mint a token for any audience.
		const grant = createClientCredentialsGrant(makeCCDeps());
		const out = await grant.handle(makeCCCtx({ resource: "https://evil.example" }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
		expect(refusalOf(out.result).errorDescription).toContain("https://evil.example");
	});

	it("allows when the derived audience represents the request", async () => {
		const grant = createClientCredentialsGrant(makeCCDeps());
		const out = await grant.handle(makeCCCtx({ resource: API }));

		expect(out.result.status).toBe(200);
	});

	it("rejects two distinct resources — a single aud cannot represent both", async () => {
		const grant = createClientCredentialsGrant(makeCCDeps());
		const out = await grant.handle(makeCCCtx({ resource: [API, OTHER] }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
	});

	it("honours a policy that narrows the audience to the requested resource", async () => {
		const grant = createClientCredentialsGrant(
			makeCCDeps({
				grantPolicy: makePolicy(async () => ({ outcome: "allow", grantedAudience: [OTHER] })),
			}),
		);
		const out = await grant.handle(makeCCCtx({ resource: OTHER }));

		expect(out.result.status).toBe(200);
	});

	it("rejects when the policy allows but narrows to a different audience", async () => {
		// Policy says yes, but the audience ends up as something the client
		// did not ask for: no token ships.
		const grant = createClientCredentialsGrant(
			makeCCDeps({
				grantPolicy: makePolicy(async () => ({ outcome: "allow", grantedAudience: [API] })),
			}),
		);
		const out = await grant.handle(makeCCCtx({ resource: OTHER }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
	});

	it("flag off: a request naming an allowed resource succeeds", async () => {
		const grant = createClientCredentialsGrant(makeCCDeps({}, false));
		const out = await grant.handle(makeCCCtx({ resource: OTHER }));

		expect(out.result.status).toBe(200);
	});

	it("no resource requested: unaffected", async () => {
		const grant = createClientCredentialsGrant(makeCCDeps());
		const out = await grant.handle(makeCCCtx());

		expect(out.result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// refresh_token
// ---------------------------------------------------------------------------

describe("RFC 8707 resource → audience binding — refresh_token", () => {
	it("derives the audience from an allowed resource when no policy narrows one", async () => {
		// Without derivation `finalAudience` stays the authenticated client id
		// and an otherwise-allowed resource would reject.
		const grant = createRefreshTokenGrant(makeRefreshDeps());
		const out = await grant.handle(makeRefreshCtx(await makeRefreshToken(), { resource: API }));

		expect(out.result.status).toBe(200);
		if (!("tokens" in out.result)) throw new Error("expected tokens");
		expect(decodeJwt(out.result.tokens.access_token).aud).toBe(API);
	});

	it("rejects invalid_target for a resource the client is not allowed", async () => {
		const grant = createRefreshTokenGrant(makeRefreshDeps());
		const out = await grant.handle(
			makeRefreshCtx(await makeRefreshToken(), { resource: "https://evil.example" }),
		);

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
	});

	it("honours a policy that narrows the audience to the requested resource", async () => {
		const grant = createRefreshTokenGrant(
			makeRefreshDeps({
				grantPolicy: makePolicy(async () => ({ outcome: "allow", grantedAudience: [API] })),
			}),
		);
		const out = await grant.handle(makeRefreshCtx(await makeRefreshToken(), { resource: API }));

		expect(out.result.status).toBe(200);
	});

	it("rejects when the policy allows but narrows to a different audience", async () => {
		const grant = createRefreshTokenGrant(
			makeRefreshDeps({
				grantPolicy: makePolicy(async () => ({ outcome: "allow", grantedAudience: [OTHER] })),
			}),
		);
		const out = await grant.handle(makeRefreshCtx(await makeRefreshToken(), { resource: API }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
	});

	it("flag off: a request naming an allowed resource succeeds", async () => {
		const grant = createRefreshTokenGrant(makeRefreshDeps({}, false));
		const out = await grant.handle(makeRefreshCtx(await makeRefreshToken(), { resource: API }));

		expect(out.result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// authorization_code
// ---------------------------------------------------------------------------

describe("RFC 8707 resource → audience binding — authorization_code (enforce-only, no policy at the token endpoint)", () => {
	it("allows when the persisted audience represents the resource presented at /token", async () => {
		const deps = makeAuthzDeps([API]);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx({ resource: API }));

		expect(out.result.status).toBe(200);
	});

	it("rejects invalid_target when the persisted audience does not represent it", async () => {
		const deps = makeAuthzDeps([API]);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx({ resource: OTHER }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
		expect(refusalOf(out.result).errorDescription).toContain(OTHER);
	});

	it("does NOT invoke the policy hook at the token endpoint", async () => {
		// The enforcement is a pure comparison against the value persisted at
		// /authorize, where the policy was evaluated once.
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const deps = makeAuthzDeps([API]);
		// Offered beside the grant's own deps, which name no policy: never consulted.
		const offered = { ...deps, grantPolicy: makePolicy(evaluate) };
		const grant = createAuthorizationGrant(offered);
		const out = await grant.handle(makeAuthzCtx({ resource: OTHER }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("rejects when the code carries no audience at all — an unbound token represents nothing", async () => {
		const deps = makeAuthzDeps(undefined);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx({ resource: API }));

		expect(out.result.status).toBe(400);
		expect(refusalOf(out.result).error).toBe("invalid_target");
	});

	it("flag off: resource at /token stays ignored", async () => {
		const deps = makeAuthzDeps([API], false);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx({ resource: OTHER }));

		expect(out.result.status).toBe(200);
	});

	it("no resource at /token: the persisted audience is used unchanged", async () => {
		const deps = makeAuthzDeps([API]);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx());

		expect(out.result.status).toBe(200);
	});
});
