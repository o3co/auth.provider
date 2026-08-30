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
 * Coverage for DPoP cnf-claim propagation in the authorization_code grant —
 * Wave 2 Phase 2 §9.1.
 *
 * Uses direct grant handler invocation (mirrors authorization.test.mts) rather
 * than full HTTP because the authorization_code flow requires PKCE, session,
 * code-repo, and redirect_uri setup that adds noise unrelated to binding
 * propagation. The binding logic is in the grant handler itself, not route
 * middleware, so direct `handler.handle(ctx)` is the right surface.
 *
 * Key behavioral contracts exercised:
 *   - AT is always bound when ctx.tokenBinding carries a confirmation
 *   - RT binding restricted to **public clients** (tokenEndpointAuthMethod === "none")
 *   - Confidential client RTs remain plain (no cnf claim) per RFC 9449 §5
 *   - token_type "DPoP" iff binding kind === "dpop"; "Bearer" otherwise
 */

import {
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const RP_URI = "https://rp.example/cb";
const CLIENT_ID = "ac-client";
const PUBLIC_CLIENT_ID = "ac-public-client";

const validCode = {
	client_id: CLIENT_ID,
	redirect_uri: RP_URI,
	// #273: PKCE is mandatory, so a redeemable code always carries an
	// S256 challenge and the token request presents the matching verifier.
	code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	code_challenge_method: "S256",
};

const validPublicCode = {
	client_id: PUBLIC_CLIENT_ID,
	redirect_uri: RP_URI,
	// #273: PKCE is mandatory, so a redeemable code always carries an
	// S256 challenge and the token request presents the matching verifier.
	code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	code_challenge_method: "S256",
};

const confidentialClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
};

const publicClient = {
	clientId: PUBLIC_CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
};

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret-ac" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			authorization_code: { enabled: true },
		},
	},
} as unknown as GrantDependencies["config"];

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

// ---------------------------------------------------------------------------
// deps helpers
// ---------------------------------------------------------------------------

function makeDeps(
	consumeByCodeImpl: CodeRepository["consumeByCode"],
	options: { readonly bindConfidentialClientRefreshTokens?: boolean } = {},
) {
	return {
		config:
			options.bindConfidentialClientRefreshTokens === undefined
				? mockConfig
				: ({
						...(mockConfig as unknown as Record<string, unknown>),
						oauth: {
							...(mockConfig as unknown as { oauth: Record<string, unknown> }).oauth,
							// `dispatch-policy` is required by CoreConfigSchema and comes
							// from reference.conf in a real deployment. Restated here so
							// the stub stays a shape the schema would accept.
							tokenBinding: {
								"dispatch-policy": "intent-explicit",
								bindConfidentialClientRefreshTokens: options.bindConfidentialClientRefreshTokens,
							},
						},
					} as unknown as GrantDependencies["config"]),
		keyStore: createSymmetricKeyStore("test-secret-ac"),
		codeRepository: {
			consumeByCode: consumeByCodeImpl,
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: mockClientRepository,
	};
}

// ---------------------------------------------------------------------------
// JWT payload decoder
// ---------------------------------------------------------------------------

function decodePayload(token: string): Record<string, unknown> {
	return decodeJwt(token) as unknown as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Base ctx template (confidential client)
// ---------------------------------------------------------------------------

const baseCtxConfidential: Omit<GrantContext, "tokenBinding"> = {
	body: {
		code: "valid-code",
		redirect_uri: RP_URI,
		code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	},
	session: {},
	issuer: "localhost",
	metadata: { ip: "127.0.0.1" },
	authenticatedClient: confidentialClient,
};

const baseCtxPublic: Omit<GrantContext, "tokenBinding"> = {
	body: {
		code: "valid-code-public",
		redirect_uri: RP_URI,
		code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	},
	session: {},
	issuer: "localhost",
	metadata: { ip: "127.0.0.1" },
	authenticatedClient: publicClient,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DPoP cnf-claim propagation — authorization_code grant (§9.1)", () => {
	describe("AT cnf propagation", () => {
		it("unbound AT + unbound RT when ctx.tokenBinding is undefined (Bearer baseline)", async () => {
			// No binding → both AT and RT are plain Bearer tokens with no cnf
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = { ...baseCtxConfidential };

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			const atPayload = decodePayload(result.tokens.access_token as string);
			expect(atPayload.cnf).toBeUndefined();
			expect(result.tokens.token_type).toBe("Bearer");

			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			expect(rtPayload.cnf).toBeUndefined();
		});

		it("DPoP-bound AT when proof is presented (confidential client)", async () => {
			// AT carries cnf.jkt; RT must NOT be bound for a confidential client (RFC 9449 §5)
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxConfidential,
				tokenBinding: { kind: "dpop", confirmation: { jkt: "AC-JKT" } },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");

			const atPayload = decodePayload(result.tokens.access_token as string);
			expect((atPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("AC-JKT");

			// Confidential client: RT MUST NOT be DPoP-bound
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			expect(rtPayload.cnf).toBeUndefined();
		});

		it("DPoP-bound AT AND DPoP-bound RT for public client", async () => {
			// Public client (tokenEndpointAuthMethod === "none"): both tokens are bound per §9.1
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validPublicCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxPublic,
				tokenBinding: { kind: "dpop", confirmation: { jkt: "AC-JKT" } },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");

			const atPayload = decodePayload(result.tokens.access_token as string);
			expect((atPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("AC-JKT");

			// Public client: RT MUST also carry cnf.jkt
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			expect((rtPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("AC-JKT");
		});
	});

	describe("token_type response wrapper", () => {
		it("token_type DPoP in response when kind === 'dpop'", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxConfidential,
				tokenBinding: { kind: "dpop", confirmation: { jkt: "AC-TYPE-JKT" } },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.token_type).toBe("DPoP");
		});

		it("public client + mTLS binding → RT bound with x5t#S256 (RFC 8705 §4 SHOULD)", async () => {
			// Phase 3 inversion of the Phase 2 deferral: mTLS-bound RT now
			// rides RFC 8705 §4 ("the authorization server SHOULD bind the
			// refresh token to the certificate the client used"). mTLS still
			// keeps wire-level token_type "Bearer" per RFC 8705 §3 — only
			// DPoP signals "DPoP" in the response wrapper. AT cnf propagation
			// remains mechanism-agnostic (RFC 7800).
			//
			// The previous "RT stays plain" assertion was pinned at PR #185
			// because there was no refresh-time mTLS enforcement matrix in
			// Phase 2. Phase 3 Sub-PR 3c adds that matrix (§9.2 mTLS rows)
			// together with this RT-binding emission, so the pair lands
			// atomically — no window where a bound RT could be refreshed
			// without proof.
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validPublicCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxPublic,
				tokenBinding: {
					kind: "mtls",
					confirmation: { "x5t#S256": "MTLS-THUMBPRINT-AC" },
				},
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			// mTLS keeps wire-level "Bearer" per RFC 8705 §3.
			expect(result.tokens.token_type).toBe("Bearer");

			// AT gets the mTLS cnf shape (mechanism-agnostic propagation)
			const atPayload = decodePayload(result.tokens.access_token as string);
			const atCnf = atPayload.cnf as Record<string, string> | undefined;
			expect(atCnf?.["x5t#S256"]).toBe("MTLS-THUMBPRINT-AC");
			expect(atCnf?.jkt).toBeUndefined();

			// Public client + mTLS → RT MUST carry cnf.x5t#S256 (RFC 8705 §4).
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			const rtCnf = rtPayload.cnf as Record<string, string> | undefined;
			expect(rtCnf?.["x5t#S256"]).toBe("MTLS-THUMBPRINT-AC");
			expect(rtCnf?.jkt).toBeUndefined();
		});

		it("confidential client + mTLS binding → RT stays plain (gate restricts to public clients)", async () => {
			// Phase 3: mTLS RT-binding mirrors DPoP's public-client gate
			// (RFC 9449 §5 rationale generalized — confidential clients
			// authenticate via client_secret at refresh time, so binding the
			// RT to the cert adds no security and would force cert retention
			// across the RT lifetime). The §9.1 comment in authorization.mts
			// is the single source of truth on this.
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxConfidential,
				tokenBinding: {
					kind: "mtls",
					confirmation: { "x5t#S256": "MTLS-THUMBPRINT-CONF" },
				},
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.token_type).toBe("Bearer");

			// AT cnf still propagates (mechanism-agnostic).
			const atPayload = decodePayload(result.tokens.access_token as string);
			expect((atPayload.cnf as { "x5t#S256"?: string } | undefined)?.["x5t#S256"]).toBe(
				"MTLS-THUMBPRINT-CONF",
			);

			// Confidential client: RT MUST stay plain regardless of mechanism.
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			expect(rtPayload.cnf).toBeUndefined();
		});
	});
});

/*
 * #275 — the same opt-in the refresh grant carries, at the point the RT is
 * first minted. Both sites had the identical `isPublicClient` gate, so both
 * have to read the same key or a confidential client would be issued a plain
 * RT here and a bound one on its first rotation.
 *
 * See `dpop.refreshToken.integration.test.mts` for why neither RFC forbids
 * this and why it is off by default.
 */
describe("confidential-client RT binding — opt-in, authorization_code (#275)", () => {
	const withBinding = (bind?: boolean) =>
		createAuthorizationGrant(
			makeDeps(
				vi.fn().mockResolvedValue({ ...validCode }),
				bind === undefined ? {} : { bindConfidentialClientRefreshTokens: bind },
			),
		);

	const dpopCtx = (): GrantContext => ({
		...baseCtxConfidential,
		tokenBinding: { kind: "dpop", confirmation: { jkt: "AC-JKT" } },
	});

	it("is off by default: the minted RT stays plain", async () => {
		const { result } = await withBinding().handle(dpopCtx());
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodePayload(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("stays off when the key is present and false", async () => {
		const { result } = await withBinding(false).handle(dpopCtx());
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodePayload(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("binds the minted RT when turned on", async () => {
		const { result } = await withBinding(true).handle(dpopCtx());
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		const rt = decodePayload(result.tokens.refresh_token as string);
		expect((rt.cnf as { jkt?: string } | undefined)?.jkt).toBe("AC-JKT");
	});

	it("binds an mTLS-authenticated confidential client's RT too", async () => {
		const { result } = await withBinding(true).handle({
			...baseCtxConfidential,
			tokenBinding: { kind: "mtls", confirmation: { "x5t#S256": "AC-X5T" } },
		});
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		const rt = decodePayload(result.tokens.refresh_token as string);
		expect((rt.cnf as Record<string, string> | undefined)?.["x5t#S256"]).toBe("AC-X5T");
	});

	it("leaves an unbound request unbound — the flag never invents a binding", async () => {
		const { result } = await withBinding(true).handle({ ...baseCtxConfidential } as GrantContext);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodePayload(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});
});
