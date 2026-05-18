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
};

const validPublicCode = {
	client_id: PUBLIC_CLIENT_ID,
	redirect_uri: RP_URI,
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

function makeDeps(consumeByCodeImpl: CodeRepository["consumeByCode"]) {
	return {
		config: mockConfig,
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
	body: { code: "valid-code", redirect_uri: RP_URI },
	session: {},
	issuer: "localhost",
	metadata: { ip: "127.0.0.1" },
	authenticatedClient: confidentialClient,
};

const baseCtxPublic: Omit<GrantContext, "tokenBinding"> = {
	body: { code: "valid-code-public", redirect_uri: RP_URI },
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

		it("token_type Bearer when kind === 'mtls' (mTLS binding shape)", async () => {
			// mTLS keeps Bearer per RFC 8705 §3; AT cnf carries x5t#S256 instead of jkt
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
			expect(result.tokens.token_type).toBe("Bearer");

			// AT gets the mTLS cnf shape
			const atPayload = decodePayload(result.tokens.access_token as string);
			const atCnf = atPayload.cnf as Record<string, string> | undefined;
			expect(atCnf?.["x5t#S256"]).toBe("MTLS-THUMBPRINT-AC");
			expect(atCnf?.jkt).toBeUndefined();

			// Public client → RT is also bound with the mTLS cnf shape
			const rtPayload = decodePayload(result.tokens.refresh_token as string);
			const rtCnf = rtPayload.cnf as Record<string, string> | undefined;
			expect(rtCnf?.["x5t#S256"]).toBe("MTLS-THUMBPRINT-AC");
		});
	});
});
