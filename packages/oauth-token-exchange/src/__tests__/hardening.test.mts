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
 * Hardening of the RFC 8693 exchange grant: the five gaps closed together
 * because each one alone leaves the escalation reachable through another.
 *
 * (a) the calling client's own `allowedScopes` is a ceiling on the granted
 *     scope, not merely the subject token's scope;
 * (b) `may_act` binds the impersonation exchange too, where the calling
 *     client is the actor and no `actor_token` is presented;
 * (c) the grant denies by absence of `allowedGrantTypes` (#326);
 * (d) the issued token's lifetime never exceeds the subject token's
 *     (RFC 8693 §2.2.1);
 * (e) a DPoP-bound issued token is advertised as `token_type: "DPoP"`
 *     (RFC 9449 §5), not as a Bearer token its own resource server refuses.
 */

import type {
	AppConfig,
	ClientRepository,
	GrantContext,
	GrantPolicyHook,
	PublicClient,
	TokenBinding,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import type { ExchangeTokenValidator, ValidatedToken } from "#/validator/types.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
/** A consumer-contributed token type, used to drive claims the built-in
 *  validator would never emit (an expired `exp`, or no `exp` at all). */
const STUB_TOKEN_TYPE = "urn:example:params:oauth:token-type:stub";

const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";
const X5T = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";

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
	allowedScopes: ["read", "write"],
	allowedAudiences: [],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
	...overrides,
});

const mockClientRepository = (client: PublicClient | null = publicClient()): ClientRepository => ({
	findById: async (id) => (id === client?.clientId ? client : null),
	authenticate: async (id) => (id === client?.clientId ? client : null),
});

/** Returns whatever `ValidatedToken` the test hands it, so claims the
 *  built-in validator cannot produce are still reachable. */
const stubValidator = (validated: ValidatedToken): ExchangeTokenValidator => ({
	async validate() {
		return validated;
	},
});

function buildGrant(
	overrides: {
		clientRepository?: ClientRepository;
		grantPolicy?: GrantPolicyHook;
		config?: AppConfig;
		stub?: ValidatedToken;
	} = {},
) {
	const store = makeFamilyRevocation();
	const registry = new ExchangeTokenValidatorRegistry();
	registry.register(
		ACCESS_TOKEN_TYPE,
		createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			refreshTokenFamilyRevocation: store,
		}),
	);
	if (overrides.stub) registry.register(STUB_TOKEN_TYPE, stubValidator(overrides.stub));
	return createTokenExchangeGrant({
		config: overrides.config ?? mockConfig,
		keyStore,
		refreshTokenFamilyRevocation: store,
		tokenExchangeValidatorResolver: registry,
		clientRepository: overrides.clientRepository ?? mockClientRepository(),
		...(overrides.grantPolicy ? { grantPolicy: overrides.grantPolicy } : {}),
	} as never);
}

const ctx = (
	body: Record<string, unknown>,
	overrides: Partial<GrantContext> = {},
): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
	authenticatedClient: null,
	...overrides,
});

const exchangeBody = (subjectToken: string, extra: Record<string, unknown> = {}) => ({
	client_id: "client-a",
	client_secret: "s",
	subject_token: subjectToken,
	subject_token_type: ACCESS_TOKEN_TYPE,
	...extra,
});

// ---------------------------------------------------------------------------
// (a) client.allowedScopes is a ceiling on the granted scope
// ---------------------------------------------------------------------------

describe("token exchange — client allowedScopes ceiling", () => {
	it("refuses an explicitly requested scope the client is not registered for", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedScopes: ["read"] })),
		});
		const token = await signSelfIssuedAccessToken({ scope: "read admin", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token, { scope: "admin" })));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_scope",
			errorDescription: expect.stringMatching(/admin/),
		});
	});

	it("does not hand a client a subject scope outside its registration when scope is omitted", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedScopes: ["read"] })),
		});
		const token = await signSelfIssuedAccessToken({ scope: "read admin", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
		expect(decodeJwt(result.tokens.access_token).scope).toBe("read");
	});

	it("grants no scope at all when the registration declares an empty allowedScopes", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedScopes: [] })),
		});
		const token = await signSelfIssuedAccessToken({ scope: "read", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBeUndefined();
	});

	it("refuses every explicit scope when the registration declares an empty allowedScopes", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedScopes: [] })),
		});
		const token = await signSelfIssuedAccessToken({ scope: "read", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token, { scope: "read" })));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_scope",
			errorDescription: expect.stringMatching(/read/),
		});
	});

	it("refuses a policy hook that grants a subject scope outside the registration", async () => {
		const policy: GrantPolicyHook = {
			kind: "grants-admin",
			async evaluate() {
				return { outcome: "allow", grantedScope: ["admin"] };
			},
		};
		const g = buildGrant({
			grantPolicy: policy,
			clientRepository: mockClientRepository(publicClient({ allowedScopes: ["read"] })),
		});
		const token = await signSelfIssuedAccessToken({ scope: "read admin", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_target",
			errorDescription: expect.stringMatching(/scope_widening_not_allowed/),
		});
	});

	it("still grants a scope the subject and the registration both carry", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token, { scope: "read write" })));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});
});

// ---------------------------------------------------------------------------
// (b) may_act binds the impersonation exchange, where the client is the actor
// ---------------------------------------------------------------------------

describe("token exchange — may_act on the impersonation path", () => {
	it("refuses an impersonation exchange by a client the subject's may_act does not name", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "svc-allowed" }],
		});
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("allows an impersonation exchange by the client the subject's may_act names", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "client-a" }],
		});
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		// Impersonation: no actor token, so no `act` chain is recorded.
		expect(decodeJwt(result.tokens.access_token).act).toBeUndefined();
	});

	it("fails closed when the may_act entry also pins an iss the client cannot present", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "client-a", iss: ISSUER }],
		});
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("fails closed on a malformed may_act with no actor_token", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", may_act: "client-a" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("leaves a subject token without may_act exchangeable by any registered client", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// (c) deny-by-absence of allowedGrantTypes (#326)
// ---------------------------------------------------------------------------

describe("token exchange — deny-by-absence of allowedGrantTypes (#326)", () => {
	it("declares requiresExplicitGrantAllowlist: true on the handler contract", () => {
		expect(buildGrant().requiresExplicitGrantAllowlist).toBe(true);
	});

	it("refuses a registration that omits allowedGrantTypes", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedGrantTypes: undefined })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({
			status: 400,
			error: "unauthorized_client",
			errorDescription: expect.stringMatching(/token-exchange/),
		});
	});

	it("refuses a registration whose allowedGrantTypes names other grants only", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedGrantTypes: ["client_credentials", "refresh_token"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({ status: 400, error: "unauthorized_client" });
	});

	it("refuses a registration with an empty allowedGrantTypes", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedGrantTypes: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result).toMatchObject({ status: 400, error: "unauthorized_client" });
	});

	it("admits a registration that names the exchange grant type", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// (d) the issued token never outlives the subject token (RFC 8693 §2.2.1)
// ---------------------------------------------------------------------------

describe("token exchange — issued lifetime is bounded by the subject token", () => {
	it("caps expires_in at the subject token's remaining lifetime", async () => {
		const g = buildGrant();
		// Configured lifetime is 300s; the subject has ~60s left.
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" }, { expiresIn: "60s" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.expires_in).toBeLessThanOrEqual(60);
		expect(result.tokens.expires_in).toBeGreaterThan(0);
		const subjectExp = decodeJwt(token).exp as number;
		expect(decodeJwt(result.tokens.access_token).exp as number).toBeLessThanOrEqual(subjectExp);
	});

	it("keeps the configured lifetime when the subject token outlives it", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" }, { expiresIn: "1h" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.expires_in).toBe(300);
	});

	it("refuses a subject token that has already expired rather than minting a dead token", async () => {
		const past = Math.floor(Date.now() / 1000) - 30;
		const g = buildGrant({
			stub: { sub: "user-1", scope: "read", claims: { sub: "user-1", exp: past } },
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "s",
				subject_token: "opaque",
				subject_token_type: STUB_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: expect.stringMatching(/expire/i),
		});
	});

	it("refuses a subject token whose remaining lifetime rounds to zero", async () => {
		const now = Math.floor(Date.now() / 1000);
		const g = buildGrant({
			stub: { sub: "user-1", scope: "read", claims: { sub: "user-1", exp: now } },
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "s",
				subject_token: "opaque",
				subject_token_type: STUB_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("leaves the configured lifetime alone when the subject token carries no exp", async () => {
		const g = buildGrant({
			stub: { sub: "user-1", scope: "read", claims: { sub: "user-1" } },
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "s",
				subject_token: "opaque",
				subject_token_type: STUB_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.expires_in).toBe(300);
	});
});

// ---------------------------------------------------------------------------
// (e) the response envelope names the mechanism the issued cnf binds
// ---------------------------------------------------------------------------

describe("token exchange — token_type matches the issued confirmation", () => {
	const dpopBinding: TokenBinding = { kind: "dpop", confirmation: { jkt: JKT } };
	const mtlsBinding: TokenBinding = { kind: "mtls", confirmation: { "x5t#S256": X5T } };

	it("advertises DPoP when the issued token carries cnf.jkt (RFC 9449 §5)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", cnf: { jkt: JKT } });
		const { result } = await g.handle(ctx(exchangeBody(token), { tokenBinding: dpopBinding }));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(decodeJwt(result.tokens.access_token).cnf).toEqual({ jkt: JKT });
		expect(result.tokens.token_type).toBe("DPoP");
	});

	it("advertises DPoP on the unbound-subject opt-in upgrade row too", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token), { tokenBinding: dpopBinding }));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.token_type).toBe("DPoP");
	});

	it("keeps Bearer for an mTLS-bound issued token (RFC 8705 §3)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			cnf: { "x5t#S256": X5T },
		});
		const { result } = await g.handle(ctx(exchangeBody(token), { tokenBinding: mtlsBinding }));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(decodeJwt(result.tokens.access_token).cnf).toEqual({ "x5t#S256": X5T });
		expect(result.tokens.token_type).toBe("Bearer");
	});

	it("keeps Bearer when the issued token is unbound", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(ctx(exchangeBody(token)));
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.token_type).toBe("Bearer");
	});
});
