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
 * Coverage for mTLS cnf-claim propagation in the authorization_code grant —
 * Wave 2 Phase 3 §9.1 (mTLS-specific). Parallel to
 * `dpop.authorizationCode.integration.test.mts` which now also includes
 * inverted mTLS regression cases — this file covers the mTLS-only path.
 *
 * Pattern: direct grant handler invocation (mirrors authorization.test.mts).
 *
 * Key behavioral contracts:
 *   - AT carries `cnf.x5t#S256` whenever ctx.tokenBinding.kind === "mtls"
 *   - RT carries cnf only for public clients (RFC 8705 §4 SHOULD)
 *   - Confidential client RTs stay plain (RFC 8705 §4 + the
 *     `bindRefreshToken` public-client gate in `authorization.mts`)
 *   - token_type stays "Bearer" regardless of mTLS binding (RFC 8705 §3)
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
const CLIENT_ID = "mtls-ac-client";
const PUBLIC_CLIENT_ID = "mtls-ac-public-client";

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
		jwt: { secret: "test-secret-mtls-ac" },
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

function makeDeps(consumeByCodeImpl: CodeRepository["consumeByCode"]) {
	return {
		config: mockConfig,
		keyStore: createSymmetricKeyStore("test-secret-mtls-ac"),
		codeRepository: {
			consumeByCode: consumeByCodeImpl,
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: mockClientRepository,
	};
}

function decodePayload(token: string): Record<string, unknown> {
	return decodeJwt(token) as unknown as Record<string, unknown>;
}

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

describe("mTLS cnf-claim propagation — authorization_code grant (§9.1)", () => {
	describe("AT cnf propagation (mechanism-agnostic per RFC 7800)", () => {
		it("confidential client + mTLS → AT bound with x5t#S256, RT plain", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxConfidential,
				tokenBinding: {
					kind: "mtls",
					confirmation: { "x5t#S256": "MTLS-AC-CONF-THUMB" },
				},
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.token_type).toBe("Bearer");
			const atCnf = decodePayload(result.tokens.access_token as string).cnf as
				| Record<string, string>
				| undefined;
			expect(atCnf?.["x5t#S256"]).toBe("MTLS-AC-CONF-THUMB");
			expect(atCnf?.jkt).toBeUndefined();
			// Confidential client: RT MUST stay plain regardless of mechanism.
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			expect(rtPayload.cnf).toBeUndefined();
		});

		it("public client + mTLS → AT bound, RT bound with same thumbprint (RFC 8705 §4 SHOULD)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validPublicCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = {
				...baseCtxPublic,
				tokenBinding: {
					kind: "mtls",
					confirmation: { "x5t#S256": "MTLS-AC-PUB-THUMB" },
				},
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.token_type).toBe("Bearer");
			const atCnf = decodePayload(result.tokens.access_token as string).cnf as
				| Record<string, string>
				| undefined;
			expect(atCnf?.["x5t#S256"]).toBe("MTLS-AC-PUB-THUMB");
			// Public client + mTLS → RT MUST carry cnf.x5t#S256 (RFC 8705 §4).
			const rtCnf = decodePayload(result.tokens.refresh_token as string).cnf as
				| Record<string, string>
				| undefined;
			expect(rtCnf?.["x5t#S256"]).toBe("MTLS-AC-PUB-THUMB");
			expect(rtCnf?.jkt).toBeUndefined();
		});
	});

	describe("no binding (Bearer baseline)", () => {
		it("unbound AT + unbound RT when ctx.tokenBinding is undefined", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ ...validPublicCode }));
			const handler = createAuthorizationGrant(deps);

			const ctx: GrantContext = { ...baseCtxPublic };

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.token_type).toBe("Bearer");
			expect(decodePayload(result.tokens.access_token as string).cnf).toBeUndefined();
			expect(decodePayload(result.tokens.refresh_token as string).cnf).toBeUndefined();
		});
	});
});
