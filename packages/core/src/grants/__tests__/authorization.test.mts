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
import crypto from "node:crypto";

import { describe, expect, it, vi } from "vitest";
import { decodeJwt } from "jose";

import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { createAuthorizationGrant } from "../authorization.mjs";
import type { GrantContext, GrantDependencies } from "../types.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
			did: { enabled: true, messageMaxAgeSec: 300 },
		},
	},
} as unknown as GrantDependencies["config"];

function makeDeps(
	consumeByCodeImpl: GrantDependencies["codeRepository"]["consumeByCode"],
): GrantDependencies {
	return {
		config: mockConfig,
		keyStore: createSymmetricKeyStore("test-secret"),
		clientRepository: {} as GrantDependencies["clientRepository"],
		codeRepository: {
			consumeByCode: consumeByCodeImpl,
			createCode: vi.fn(),
			getByCode: vi.fn(),
			removeByCode: vi.fn(),
		},
	};
}

describe("createAuthorizationGrant", () => {
	describe("handle", () => {
		it("returns 400 when code is missing", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", code_challenge: undefined }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
		});

		it("returns 400 when code does not match session code", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "wrong-code", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when client_id does not match session code_client_id", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "wrong-client" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when codeRepository.consumeByCode returns null", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 with access and refresh tokens on valid code exchange (no PKCE)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result, sessionMutation } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.refresh_token).toBeDefined();
				const decoded = decodeJwt(result.tokens.access_token);
				expect(decoded.sub).toBe("u1");
				expect((decoded as Record<string, unknown>).azp).toBe("client1");
			}
			// Session must be cleared
			expect(sessionMutation).toBeDefined();
			expect(sessionMutation?.clear).toContain("code");
			expect(sessionMutation?.clear).toContain("code_client_id");
			expect(sessionMutation?.clear).toContain("granted_scopes");
		});

		it("returns 400 when PKCE is required but code_verifier is missing", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when code_verifier has invalid format", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: "too-short" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when S256 code_verifier does not match challenge", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "wrong-challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			// Valid format verifier that won't match the challenge
			const verifier = "a".repeat(43);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 when S256 PKCE code_verifier is valid", async () => {
			const verifier = "a".repeat(43);
			const hash = crypto.createHash("sha256").update(verifier).digest();
			const challenge = hash.toString("base64url");

			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 200 when plain PKCE code_verifier matches challenge", async () => {
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});
	});
});
