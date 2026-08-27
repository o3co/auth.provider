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
 * RFC 8707 Stage 2 — library-level resource → audience binding enforcement
 * (#173).
 *
 * Stage 1 (PR #172) forwarded `body.resource` to the policy hook and stopped
 * there: nothing checked that the token actually got minted for the requested
 * resource. These tests pin the enforcement.
 *
 * The rule, generalised from the token-exchange grant's IH-8 hardening: when
 * the flag is on and `resource` is present, every requested resource must be
 * represented by the token's `aud`, or the response is `400 invalid_target`.
 * `aud` is single-valued, so two distinct resources are unsatisfiable by
 * construction.
 *
 * Enforcement is gated on the flag ALONE, not on a policy hook being wired.
 * A deployment that turns the flag on without a policy still derives an
 * audience (`client.allowedAudiences[0] ?? issuer`), and issuing that token in
 * response to a mismatched `resource` request is exactly the RFC 8707 §2
 * violation Stage 2 exists to close.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuthenticatedClient,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHook,
} from "@o3co/auth-provider-core";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";

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
	allowedAudiences: [API, OTHER],
};

const makePolicy = (evaluate: GrantPolicyHook["evaluate"]): GrantPolicyHook => ({
	kind: "stub",
	evaluate,
});

// ----- client_credentials -----

function makeCCDeps(extra: Partial<GrantDependencies> = {}, enabled = true): GrantDependencies {
	return {
		config: {
			oauth: {
				jwt: { issuer: "https://test.example" },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				resourceIndicator: { enabled },
			},
		} as unknown as GrantDependencies["config"],
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
): GrantDependencies {
	return {
		config: {
			oauth: {
				jwt: { secret: SECRET },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject" },
				grants: {
					authorization_code: { enabled: true },
					refresh_token: { enabled: true },
				},
				resourceIndicator: { enabled },
			},
		} as unknown as GrantDependencies["config"],
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
): GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository } {
	return {
		config: {
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
		} as unknown as GrantDependencies["config"],
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository: {
			consumeByCode: vi.fn().mockResolvedValue({
				client_id: CLIENT_ID,
				redirect_uri: RP_URI,
				// #273: a redeemable code always carries an S256 challenge.
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
		allowedAudiences: [API, OTHER],
	},
});

// ---------------------------------------------------------------------------
// client_credentials
// ---------------------------------------------------------------------------

describe("Stage 2 — client_credentials", () => {
	it("derives the audience from an allowed resource when no policy narrows one", async () => {
		// Acceptance criterion 1, third bullet: without this the audience would
		// fall back to allowedAudiences[0] = API and a request for OTHER would
		// reject, making RFC 8707 unusable unless a policy hook is wired.
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
		expect(out.result.error).toBe("invalid_target");
		expect(out.result.errorDescription).toContain("https://evil.example");
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
		expect(out.result.error).toBe("invalid_target");
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
		// The Stage 1 gap: policy says yes, audience ends up as something the
		// client did not ask for, and the token used to ship anyway.
		const grant = createClientCredentialsGrant(
			makeCCDeps({
				grantPolicy: makePolicy(async () => ({ outcome: "allow", grantedAudience: [API] })),
			}),
		);
		const out = await grant.handle(makeCCCtx({ resource: OTHER }));

		expect(out.result.status).toBe(400);
		expect(out.result.error).toBe("invalid_target");
	});

	it("flag off: no enforcement, pre-Stage-2 behaviour preserved", async () => {
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

describe("Stage 2 — refresh_token", () => {
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
		expect(out.result.error).toBe("invalid_target");
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
		expect(out.result.error).toBe("invalid_target");
	});

	it("flag off: no enforcement, pre-Stage-2 behaviour preserved", async () => {
		const grant = createRefreshTokenGrant(makeRefreshDeps({}, false));
		const out = await grant.handle(makeRefreshCtx(await makeRefreshToken(), { resource: API }));

		expect(out.result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// authorization_code
// ---------------------------------------------------------------------------

describe("Stage 2 — authorization_code (enforce-only, no policy at the token endpoint)", () => {
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
		expect(out.result.error).toBe("invalid_target");
		expect(out.result.errorDescription).toContain(OTHER);
	});

	it("does NOT invoke the policy hook at the token endpoint (C-2 / D-1 preserved)", async () => {
		// The enforcement is a pure comparison against the value persisted at
		// /authorize. Re-running policy here would reintroduce the surface D-1
		// removed, so the invariant is asserted alongside the new behaviour
		// rather than left to the Stage 1 test to defend.
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const deps = makeAuthzDeps([API]);
		const grant = createAuthorizationGrant({ ...deps, grantPolicy: makePolicy(evaluate) });
		const out = await grant.handle(makeAuthzCtx({ resource: OTHER }));

		expect(out.result.status).toBe(400);
		expect(out.result.error).toBe("invalid_target");
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("rejects when the code carries no audience at all — an unbound token represents nothing", async () => {
		const deps = makeAuthzDeps(undefined);
		const grant = createAuthorizationGrant(deps);
		const out = await grant.handle(makeAuthzCtx({ resource: API }));

		expect(out.result.status).toBe(400);
		expect(out.result.error).toBe("invalid_target");
	});

	it("flag off: resource at /token stays ignored, as in Stage 1", async () => {
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
