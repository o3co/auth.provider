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
import {
	type AuthenticatedClient,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);

const CLIENT_ID = "c-1";

const baseDeps: GrantDependencies = {
	config: {
		oauth: {
			jwt: { issuer: "https://test.example" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
		},
	} as unknown as GrantDependencies["config"],
	keyStore,
};

function makeClient(overrides: Partial<AuthenticatedClient> = {}): AuthenticatedClient {
	return {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedScopes: ["read:foo", "write:foo"],
		// #396: the old implicit omitted-scope grant, now declared.
		defaultScopes: ["read:foo", "write:foo"],
		allowedAudiences: ["https://rs"],
		allowedGrantTypes: ["client_credentials"],
		...overrides,
	};
}

function makeCtx(
	client: AuthenticatedClient | null,
	body: Record<string, unknown> = { grant_type: "client_credentials" },
): GrantContext {
	return {
		body,
		session: {},
		issuer: "https://test.example",
		metadata: {},
		authenticatedClient: client,
	};
}

describe("createClientCredentialsGrant — gates", () => {
	it("returns 401 invalid_client when no authenticated client", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const { result } = await handler.handle(makeCtx(null));

		expect(result.status).toBe(401);
		expect("error" in result && result.error).toBe("invalid_client");
	});

	it("returns 400 invalid_client for public clients (tokenEndpointAuthMethod === 'none')", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ tokenEndpointAuthMethod: "none" });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_client");
		expect("errorDescription" in result && result.errorDescription).toContain("confidential");
	});

	it("declares requiresExplicitGrantAllowlist: true on the handler contract (#326)", () => {
		// The allowedGrantTypes gate (deny-by-absence included) moved out of
		// this handler and onto the shared `/token` dispatch: the handler
		// declares strictness, `routes.mts` enforces it together with the base
		// rule before `handle` runs. This pin is what keeps the declaration
		// from silently disappearing; the enforcement itself is pinned at
		// dispatch level in `allowedGrantTypes.enforcement.test.mts` and, for
		// this concrete grant, in `clientCredentials.integration.test.mts`.
		const handler = createClientCredentialsGrant(baseDeps);

		expect(handler.requiresExplicitGrantAllowlist).toBe(true);
	});
});

describe("createClientCredentialsGrant — token issuance", () => {
	it("issues AT with sub=client_id and no refresh_token", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient();

		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "read:foo" }),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		expect(result.tokens.access_token).toBeTruthy();
		// RFC 6749 §4.4.3: client_credentials does not issue a refresh_token.
		expect(result.tokens.refresh_token).toBeUndefined();

		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.sub).toBe(CLIENT_ID);
		expect(payload.client_id).toBe(CLIENT_ID);
		expect(payload.azp).toBe(CLIENT_ID);
		expect(payload.scope).toBe("read:foo");
	});

	// #396: an omitted scope draws on the client's DECLARED default — never on
	// the whole allowlist, which made "forgot to send scope" the maximum grant.
	it("grants defaultScopes when scope is omitted and the client declares them", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["s1", "s2"], defaultScopes: ["s1"] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.scope).toBe("s1");
	});

	it("returns 400 invalid_scope when scope is omitted and no defaultScopes are declared", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["s1", "s2"], defaultScopes: undefined });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		if (!("error" in result)) throw new Error("expected error in result");
		expect(result.error).toBe("invalid_scope");
	});

	it("keeps the empty grant for a scope-less client (empty allowlist, no defaults)", async () => {
		// The carve-out: nothing to over-grant, so scope-less deployments work.
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: [], defaultScopes: undefined });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.scope).toBeUndefined();
	});

	it("returns 400 invalid_scope when requested scope is not in allowedScopes", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["read:foo"] });

		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "admin:all" }),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toContain("admin:all");
	});

	it("returns 400 invalid_request when scope is a non-string value (Codex review #1)", async () => {
		// Express urlencoded body-parser materializes repeated `scope=a&scope=b`
		// form parameters into arrays. RFC 6749 §3.3 requires a single space-
		// delimited string. Silently defaulting to the client's full allowedScopes
		// (the pre-fix behavior) would grant broader scope than the caller submitted.
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["read:foo", "write:foo"] });

		const { result } = await handler.handle(
			makeCtx(client, {
				grant_type: "client_credentials",
				scope: ["read:foo", "write:foo"] as unknown as string,
			}),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
		expect("errorDescription" in result && result.errorDescription).toContain("string");
	});

	it("uses allowedAudiences[0] as the aud claim when present", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedAudiences: ["https://api.example"] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://api.example");
	});

	it("falls back to issuer as aud when allowedAudiences is absent", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedAudiences: undefined });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://test.example");
	});

	it("omits iss and aud claims when ctx.issuer is undefined (Claude review C1)", async () => {
		// Coercing ctx.issuer to "" (the pre-fix behavior) would emit a malformed
		// `iss: ""` claim — generateToken treats empty string as present because
		// the guard is `issuer != null` (not falsy). Sibling grants
		// (authorization_code, refresh_token) pass ctx.issuer through directly so
		// undefined → claim omitted; this grant must match that contract.
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedAudiences: undefined });

		const { result } = await handler.handle({
			body: { grant_type: "client_credentials" },
			session: {},
			issuer: undefined,
			metadata: {},
			authenticatedClient: client,
		});

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.iss).toBeUndefined();
		// aud also omitted because allowedAudiences[0] is undefined and issuer
		// is undefined → falls through to null → generateToken drops the claim.
		expect(payload.aud).toBeUndefined();
	});
});

describe("createClientCredentialsGrant — grantPolicy scope validation (CP-18 fail-closed)", () => {
	const depsWithPolicy = (
		evaluate: (input: Record<string, unknown>) => Promise<{
			outcome: "allow" | "deny";
			grantedScope?: string[];
			grantedAudience?: string[];
			error?: string;
			errorDescription?: string;
		}>,
	): GrantDependencies => ({
		...baseDeps,
		config: {
			oauth: {
				...baseDeps.config.oauth,
				resourceIndicator: { enabled: true },
			},
		} as unknown as GrantDependencies["config"],
		grantPolicy: {
			evaluate: evaluate as unknown as GrantDependencies["grantPolicy"],
		} as unknown as GrantDependencies["grantPolicy"],
	});

	it("accepts policy grantedScope that is a subset of allowedScopes and mints with narrowed scope", async () => {
		// Policy narrows read:foo + write:foo → read:foo only. Handler must accept.
		const client = makeClient({ allowedScopes: ["read:foo", "write:foo"] });
		const handler = createClientCredentialsGrant(
			depsWithPolicy(async () => ({ outcome: "allow", grantedScope: ["read:foo"] })),
		);

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.scope).toBe("read:foo");
	});

	it("rejects policy grantedScope that exceeds allowedScopes with 400 invalid_scope (CP-18)", async () => {
		// Policy returns 'admin' which is NOT in client.allowedScopes → fail-closed.
		const client = makeClient({ allowedScopes: ["read:foo"] });
		const handler = createClientCredentialsGrant(
			depsWithPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["read:foo", "admin"],
			})),
		);

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toContain("admin");
	});
});

describe("createClientCredentialsGrant — grantPolicy audience validation (Codex P2-3)", () => {
	const depsWithAudiencePolicy = (
		evaluate: (input: Record<string, unknown>) => Promise<{
			outcome: "allow" | "deny";
			grantedScope?: string[];
			grantedAudience?: string[];
			error?: string;
			errorDescription?: string;
		}>,
	): GrantDependencies => ({
		...baseDeps,
		config: {
			oauth: {
				...baseDeps.config.oauth,
				resourceIndicator: { enabled: true },
			},
		} as unknown as GrantDependencies["config"],
		grantPolicy: {
			evaluate: evaluate as unknown as GrantDependencies["grantPolicy"],
		} as unknown as GrantDependencies["grantPolicy"],
	});

	it("uses policy grantedAudience when it is within allowedAudiences (subset check)", async () => {
		// Client allows ["https://rs1", "https://rs2"]; policy narrows to
		// ["https://rs2"]. Token aud must be https://rs2 (not allowedAudiences[0]).
		const client = makeClient({
			allowedAudiences: ["https://rs1", "https://rs2"],
		});
		const handler = createClientCredentialsGrant(
			depsWithAudiencePolicy(async () => ({
				outcome: "allow",
				grantedAudience: ["https://rs2"],
			})),
		);

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://rs2");
	});

	it("rejects policy grantedAudience outside allowedAudiences with 400 invalid_request", async () => {
		// Policy returns an audience not in client.allowedAudiences → fail-closed.
		const client = makeClient({ allowedAudiences: ["https://rs1"] });
		const handler = createClientCredentialsGrant(
			depsWithAudiencePolicy(async () => ({
				outcome: "allow",
				grantedAudience: ["https://other.example"],
			})),
		);

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
		expect("errorDescription" in result && result.errorDescription).toContain(
			"https://other.example",
		);
	});

	it("falls back to allowedAudiences[0] when policy returns no grantedAudience", async () => {
		// Policy omits grantedAudience (outcome: allow, no audience field).
		// Existing fallback behavior (allowedAudiences[0]) must be preserved.
		const client = makeClient({ allowedAudiences: ["https://api.example"] });
		const handler = createClientCredentialsGrant(
			depsWithAudiencePolicy(async () => ({ outcome: "allow" })),
		);

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://api.example");
	});
});

describe("createClientCredentialsGrant — grantPolicy scope ceiling (Codex Round 2 P1)", () => {
	const depsWithPolicy = (
		evaluate: (input: Record<string, unknown>) => Promise<{
			outcome: "allow" | "deny";
			grantedScope?: string[];
			grantedAudience?: string[] | undefined;
			error?: string;
			errorDescription?: string;
		}>,
	): GrantDependencies => ({
		...baseDeps,
		config: {
			oauth: {
				...baseDeps.config.oauth,
				resourceIndicator: { enabled: true },
			},
		} as unknown as GrantDependencies["config"],
		grantPolicy: {
			evaluate: evaluate as unknown as GrantDependencies["grantPolicy"],
		} as unknown as GrantDependencies["grantPolicy"],
	});

	it("returns 400 when policy grantedScope is outside the requested (effectiveScopes) set even if within allowedScopes (Codex Round 2 P1-1)", async () => {
		// Client allowedScopes: ["read", "write"]. Request narrows to scope=read.
		// effectiveScopes becomes ["read"]. Policy returns grantedScope: ["write"].
		// write ∈ allowedScopes but NOT ∈ effectiveScopes (the requested set).
		// Ceiling must be effectiveScopes, not client.allowedScopes.
		const client = makeClient({ allowedScopes: ["read", "write"] });
		const handler = createClientCredentialsGrant(
			depsWithPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["write"],
				grantedAudience: undefined,
			})),
		);

		// No `resource` here: this case is about the scope ceiling. Under
		// Stage 1 the parameter was inert, so carrying it was harmless; under
		// Stage 2 (#173) it is enforced against the issued audience, which
		// would couple a scope test to audience configuration and could make it
		// pass for the wrong reason if the two checks were ever reordered.
		// RFC 8707 forwarding has its own coverage in
		// `resourceIndicator.flag.test.mts`.
		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "read" }),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toContain("write");
	});

	it("honors empty grantedScope: [] from policy as 'strip all scopes' (Codex Round 2 P1-2)", async () => {
		// Policy explicitly returns grantedScope: [] — intent is "allow the grant
		// but issue no scopes". The empty array must be applied (effectiveScopes = [])
		// so the token has no scope claim, not the pre-policy effectiveScopes.
		const client = makeClient({ allowedScopes: ["read"] });
		const handler = createClientCredentialsGrant(
			depsWithPolicy(async () => ({
				outcome: "allow",
				grantedScope: [],
				grantedAudience: undefined,
			})),
		);

		// See the sibling case above: `resource` is dropped because this test is
		// about scope stripping. With Stage 2 (#173) enforcing it, the policy
		// here returns `grantedAudience: undefined`, so the audience falls back
		// to allowedAudiences[0] and a request for `https://rs1` would now
		// correctly reject with `invalid_target` — a true result, but not the
		// one this case exists to assert.
		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "read" }),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		// After policy strip, scope claim should be absent or empty string.
		expect(payload.scope ?? "").toBe("");
	});
});
