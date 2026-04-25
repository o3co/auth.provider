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
	type ClientRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization_code: { enabled: true },
			refresh_token: { enabled: true },
		},
	},
} as unknown as GrantDependencies["config"];

const makeDeps = (
	overrides?: Partial<GrantDependencies & { clientRepository: ClientRepository }>,
) => ({
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	clientRepository: {
		findById: vi.fn(),
		authenticate: vi.fn(),
	} as unknown as ClientRepository,
	...overrides,
});

const mockDeps = makeDeps();

describe("createSessionGrant", () => {
	describe("handle", () => {
		it("returns 401 when session is not authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: false },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(401);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("unauthorized");
			}
		});

		it("returns 401 when session has no isAuthenticated field", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(401);
		});

		it("returns 200 with access token when session is authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {
					isAuthenticated: true,
					user: { id: "user1", name: "Alice" },
					client: { id: "client1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.token_type).toBe("Bearer");
				expect(result.tokens.refresh_token).toBeUndefined();
			}
		});

		it("includes metadata in token payload instead of req.ip", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {
					isAuthenticated: true,
					user: { id: "user1" },
				},
				issuer: "localhost",
				metadata: { ip: "192.168.1.1", customField: "value" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("includes audience when client_id is provided", async () => {
			const deps = makeDeps();
			(deps.clientRepository.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
				clientId: "my-app",
				allowedRedirectUris: [],
				allowedScopes: ["read", "write"],
			});
			const handler = createSessionGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "my-app" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				const decoded = decodeJwt(result.tokens.access_token);
				expect(decoded.aud).toBe("my-app");
				expect(decoded.sub).toBe("u1");
				expect((decoded as Record<string, unknown>).azp).toBe("my-app");
			}
		});

		it("validates scope against client allowedScopes when client_id is provided", async () => {
			const deps = makeDeps();
			(deps.clientRepository.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
				clientId: "my-app",
				allowedRedirectUris: [],
				allowedScopes: ["read", "write"],
			});
			const handler = createSessionGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "my-app", scope: "read" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("rejects scope exceeding client allowedScopes", async () => {
			const deps = makeDeps();
			(deps.clientRepository.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
				clientId: "my-app",
				allowedRedirectUris: [],
				allowedScopes: ["read"],
			});
			const handler = createSessionGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "my-app", scope: "read admin" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("invalid_scope");
			}
		});

		it("returns 400 when client_id is provided but client not found", async () => {
			const deps = makeDeps();
			(deps.clientRepository.findById as ReturnType<typeof vi.fn>).mockResolvedValue(null);
			const handler = createSessionGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "unknown" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
		});

		it("accepts scope without client_id (no validation)", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read write" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read write");
			}
		});

		it("deduplicates scope values", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read read write" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read write");
			}
		});

		it("treats empty scope string as no scope", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBeUndefined();
			}
		});

		it("does not return sessionMutation", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true },
				issuer: "localhost",
				metadata: {},
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});
});
