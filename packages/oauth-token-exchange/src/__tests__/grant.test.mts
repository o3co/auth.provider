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

import type {
	AppConfig,
	ClientRepository,
	GrantContext,
	GrantPolicyContext,
	GrantPolicyHookBase,
	GrantPolicyRequest,
	PublicClient,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const mockConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

const publicClient = (overrides: Partial<PublicClient> = {}): PublicClient => ({
	clientId: "client-a",
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
	...overrides,
});

const mockClientRepository = (client: PublicClient | null = publicClient()): ClientRepository => ({
	findById: async (id) => (id === client?.clientId ? client : null),
	authenticate: async (id, _secret) => (id === client?.clientId ? client : null),
});

function buildGrant(
	overrides: {
		validatorRegistry?: ExchangeTokenValidatorRegistry;
		clientRepository?: ClientRepository;
		/** Pass `null` to explicitly omit the store from deps (fail-closed tests). */
		refreshTokenFamilyRevocation?: ReturnType<typeof makeFamilyRevocation> | null;
		/** Store wired into the validator (defaults to same as refreshTokenFamilyRevocation). */
		validatorRefreshStore?: ReturnType<typeof makeFamilyRevocation> | null;
		config?: AppConfig;
		grantPolicy?: GrantPolicyHookBase;
	} = {},
) {
	const registry = overrides.validatorRegistry ?? new ExchangeTokenValidatorRegistry();
	// null = explicitly absent; undefined = use default
	const grantStore =
		overrides.refreshTokenFamilyRevocation === null
			? undefined
			: (overrides.refreshTokenFamilyRevocation ?? makeFamilyRevocation());
	// validatorRefreshStore defaults to same as grantStore unless explicitly overridden
	const validatorStore =
		"validatorRefreshStore" in overrides
			? (overrides.validatorRefreshStore ?? undefined)
			: (grantStore ?? undefined);
	if (!overrides.validatorRegistry) {
		registry.register(
			ACCESS_TOKEN_TYPE,
			createSelfIssuedAccessTokenValidator({
				keyStore,
				refreshTokenFamilyRevocation: validatorStore,
				issuer: ISSUER,
			}),
		);
	}
	return createTokenExchangeGrant({
		config: overrides.config ?? mockConfig,
		keyStore,
		refreshTokenFamilyRevocation: grantStore,
		// ExchangeTokenValidatorRegistry exposes structurally-compatible
		// `.get()` for the resolver; A2-γ §3.3 keeps the registry class as
		// test scaffolding even though it is no longer publicly exported.
		tokenExchangeValidatorResolver: registry,
		clientRepository: overrides.clientRepository ?? mockClientRepository(),
		...(overrides.grantPolicy ? { grantPolicy: overrides.grantPolicy } : {}),
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
});

describe("createTokenExchangeGrant — request errors", () => {
	it("returns invalid_request when subject_token is missing", async () => {
		const g = buildGrant();
		const { result } = await g.handle(
			ctx({ client_id: "client-a", subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when subject_token_type is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(ctx({ client_id: "client-a", subject_token: token }));
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when client_id is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({ subject_token: token, subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_client when client cannot be authenticated", async () => {
		const g = buildGrant({ clientRepository: mockClientRepository(null) });
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "unknown",
				client_secret: "x",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 401, error: "invalid_client" });
	});

	it("returns unsupported_token_type when subject_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when requested_token_type is not access_token", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when actor_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: "any",
				actor_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("mints a token for the minimal happy-path input (was Task 6 stub guard)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
	});

	it("rejects client_secret as array (prevents auth bypass via repeated params)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: ["x", "y"], // repeated params → array
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});

	it.each([
		["number", 123],
		["object", { a: 1 }],
		["boolean", true],
	])("rejects client_secret with non-string type %s", async (_label, badValue) => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: badValue,
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});

	it("rejects actor_token_type without actor_token (prevents delegation-policy bypass)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token_type: ACCESS_TOKEN_TYPE, // no actor_token
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/actor_token is required/),
		});
	});

	it("rejects actor_token without actor_token_type (symmetric guard)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor, // no actor_token_type
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/actor_token_type is required/),
		});
	});

	it("rejects request when client_secret is omitted (confidential clients only)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 401,
			error: "invalid_client",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});
});

describe("createTokenExchangeGrant — token validation", () => {
	it("returns invalid_grant when subject_token signature is invalid", async () => {
		const g = buildGrant();
		const token = `${(await signSelfIssuedAccessToken({})).slice(0, -4)}AAAA`;
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("returns invalid_grant/family_revoked when subject family is revoked", async () => {
		const store = makeFamilyRevocation({
			isFamilyRevoked: async (id) => id === "fam-bad",
		});
		// validatorRefreshStore: null → validator has no store, so it returns a
		// ValidatedToken with familyId set (doesn't self-check revocation).
		// The grant's re-surface block then consults `refreshTokenFamilyRevocation` and
		// surfaces the `family_revoked` errorDescription.
		const g = buildGrant({ refreshTokenFamilyRevocation: store, validatorRefreshStore: null });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-bad" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "family_revoked",
		});
	});

	it("returns invalid_grant when refreshTokenFamilyRevocation is not wired (fail-closed)", async () => {
		// refreshTokenFamilyRevocation: null → deps.refreshTokenFamilyRevocation is undefined (absent).
		// validatorRefreshStore: null → validator has no store, so it returns a
		// ValidatedToken with familyId (doesn't self-check revocation).
		// The grant's fail-closed check fires: familyId present + no store → 400.
		const g = buildGrant({ refreshTokenFamilyRevocation: null, validatorRefreshStore: null });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("returns temporarily_unavailable (503) when validator throws (runtime store failure)", async () => {
		const store = makeFamilyRevocation({
			isFamilyRevoked: async () => {
				throw new Error("redis down");
			},
		});
		const g = buildGrant({ refreshTokenFamilyRevocation: store });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("returns invalid_grant when actor_token fails validation", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const badActor = `${(await signSelfIssuedAccessToken({ sub: "svc-a" })).slice(0, -4)}AAAA`;
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: badActor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});
});

describe("createTokenExchangeGrant — narrowing checks", () => {
	it("returns invalid_scope when requested scope is a superset of subject scope", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_scope" });
	});

	it("returns invalid_target when audience is not in allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "inventory",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("mints a token when audience matches clientId even without allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "client-a",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status === 200) {
			expect(result.tokens.access_token).toBeDefined();
			expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
			expect(result.tokens.token_type).toBe("Bearer");
			expect(result.tokens.refresh_token).toBeFalsy();
		}
	});

	it("mints a token when multi-value audience entries are in allowlist ∪ {clientId}", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: ["billing", "inventory"],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("mints a token when audience is empty array (treated as no audience requested)", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: [],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("mints a token when audience array contains only empty strings (filtered to none)", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: ["", ""],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("treats scope='' as omitted (inherits subject scope, not explicit empty)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		// Scope was explicitly empty → normalized to "omitted" → inherited.
		expect(result.tokens.scope).toBe("read write");
	});

	it("treats scope='  ' (whitespace-only) as omitted (inherits subject scope)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "   ",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});
});

describe("createTokenExchangeGrant — audience inheritance", () => {
	it("rejects inherited subject.aud when not in client allowlist (cross-client confusion)", async () => {
		// Subject token was issued with aud="a-api" (for Client A).
		// Our handler's client is client-a but has allowedAudiences=[].
		// When audience request parameter is omitted, we must NOT silently
		// inherit "a-api" (which would be permissive) — fall back to clientId.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "a-api", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		// aud must be the clientId (fallback), NOT the inherited subject.aud
		expect(payload.aud).toBe("client-a");
	});

	it("inherits subject.aud when it matches client allowlist (happy path)", async () => {
		// Subject issued with aud="billing". Client has allowedAudiences including "billing".
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "billing", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("inherits subject.aud when it matches clientId (default allowlist)", async () => {
		// Subject issued with aud=clientId. No allowedAudiences configured.
		// This is the common case for non-Token-Exchange access_tokens.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "client-a", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});

	it("inherits subject.aud when encoded as a single-element array (RFC 7519 §4.1.3)", async () => {
		// RFC 7519 permits aud as a string OR an array. A single-element array
		// is semantically equivalent to a bare string and must not silently fall
		// back to clientId.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: ["billing"], family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("falls back to clientId when subject.aud is a multi-element array", async () => {
		// Multi-valued audience cannot be represented in a single-aud token.
		// Falling back to clientId is the safe choice (no surprise widening).
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["billing", "inventory"],
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});

	it("rejects single-element-array subject.aud when not in allowlist", async () => {
		// Same cross-client confusion defense as the string case.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: ["a-api"], family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});
});

const denyPolicy: GrantPolicyHookBase = {
	kind: "deny-all",
	async evaluate() {
		return { outcome: "deny", error: "access_denied" };
	},
};

const overridePolicy: GrantPolicyHookBase = {
	kind: "override",
	async evaluate(_req: GrantPolicyRequest, _ctx: GrantPolicyContext) {
		return {
			outcome: "allow",
			grantedScope: ["read"],
			grantedAudience: ["billing"],
		};
	},
};

describe("createTokenExchangeGrant — happy path", () => {
	it("mints an access_token with issued_token_type set (minimal impersonation)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.access_token).toBeDefined();
		expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(result.tokens.refresh_token).toBeFalsy();
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.sub).toBe("user-1");
		expect(payload.family_id).toBe("fam-1");
		expect(payload.act).toBeUndefined();
	});

	it("inherits subject scope when scope parameter is omitted", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});

	it("narrows scope to requested subset", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
	});

	it("adds act claim when actor_token is provided (delegation)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-a" });
	});

	it("nests subject.act inside new act for multi-step delegation", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			act: { sub: "svc-upstream" },
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-b", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-b", act: { sub: "svc-upstream" } });
	});

	it("inherits family_id from subject (cascade revoke)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-xyz" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.family_id).toBe("fam-xyz");
	});
});

describe("createTokenExchangeGrant — policy hook", () => {
	it("rejects with access_denied when policy hook denies", async () => {
		const g = buildGrant({ grantPolicy: denyPolicy });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 403, error: "access_denied" });
	});

	it("applies policy hook grantedScope / grantedAudience overrides", async () => {
		const g = buildGrant({
			grantPolicy: overridePolicy,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
				audience: ["billing", "inventory"],
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("returns temporarily_unavailable (503) when policy hook throws", async () => {
		const throwing: GrantPolicyHookBase = {
			kind: "throw",
			async evaluate() {
				throw new Error("policy infrastructure down");
			},
		};
		const g = buildGrant({ grantPolicy: throwing });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("documents that policy hook may widen scope beyond subject (by design — see spec §8.1 rule 4)", async () => {
		// This test documents the intentional widening behavior. The built-in
		// scope subset check (requested ⊆ subject) is NOT re-applied to policy
		// hook output. Consumers who install a widening policy accept the
		// consequences per spec §8.1.
		const wideningPolicy: GrantPolicyHookBase = {
			kind: "widening",
			async evaluate() {
				return {
					outcome: "allow",
					grantedScope: ["read", "write", "admin"], // wider than subject's "read"
				};
			},
		};
		const g = buildGrant({ grantPolicy: wideningPolicy });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		// Policy successfully widened scope — this is the documented behavior.
		expect(result.tokens.scope).toBe("read write admin");
	});

	it("passes resource parameter through to the policy hook request", async () => {
		let captured: GrantPolicyRequest | null = null;
		const capturing: GrantPolicyHookBase = {
			kind: "capture",
			async evaluate(req) {
				captured = req;
				return { outcome: "allow" };
			},
		};
		const g = buildGrant({ grantPolicy: capturing });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: "https://api.example.com",
			}),
		);
		expect(captured).not.toBeNull();
		expect(captured?.resource).toEqual(["https://api.example.com"]);
	});
});
