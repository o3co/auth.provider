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
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
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

const makeDeps = (overrides?: Partial<GrantDependencies>) => ({
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	...overrides,
});

const mockDeps = makeDeps();

// #260: every /token request reaches a grant through `clientAuthMw`, so
// `ctx.authenticatedClient` is always populated in production. Tests that are
// not about client authentication itself supply this default so they exercise
// the same shape the route does.
const AUTH_CLIENT = {
	clientId: "my-app",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["read", "write"],
};

describe("createSessionGrant", () => {
	describe("handle", () => {
		it("returns 401 when session is not authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: false },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("binds audience and azp to the authenticated client", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
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

		it("validates scope against the authenticated client's allowedScopes", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("rejects scope exceeding client allowedScopes", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read admin" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("invalid_scope");
			}
		});

		it("ignores a body client_id naming a different client", async () => {
			// clientAuthMw rejects a body client_id that contradicts Basic
			// credentials, so this shape cannot reach the grant through /token.
			// The assertion pins that identity is read from the authenticated
			// slot regardless, rather than relying on that upstream check alone.
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { client_id: "other-app", scope: "read" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("my-app");
				expect(decoded.azp).toBe("my-app");
			}
		});

		it("grants the requested scope when it is within the allowlist", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read write" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBeUndefined();
			}
		});

		// -------------------------------------------------------------------
		// #260 — the grant must authorize against the *authenticated* client
		//
		// `clientAuthMw` runs before every grant on /token and populates
		// `ctx.authenticatedClient`. When the client authenticates with HTTP
		// Basic — the canonical transport for a confidential client — its
		// `client_id` lives in the Authorization header and never appears in
		// the body, so a grant that reads `body.client_id` to find the client
		// sees nothing and skips its allowlist entirely.
		// -------------------------------------------------------------------
		describe("#260 — authorization binds to ctx.authenticatedClient", () => {
			const basicAuthClient = {
				clientId: "first-party-app",
				tokenEndpointAuthMethod: "client_secret_basic" as const,
				allowedScopes: ["read"],
			};

			it("enforces allowedScopes for a Basic-authenticated client that sends no body client_id", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					// Basic credentials are consumed by clientAuthMw; the body carries
					// only the grant parameters.
					body: { scope: "admin:*" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: basicAuthClient,
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_scope");
			});

			it("binds aud and azp to the authenticated client rather than the body", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "read" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: basicAuthClient,
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("first-party-app");
				expect(decoded.azp).toBe("first-party-app");
			});

			it("uses the client's configured audience when one is registered", async () => {
				// Forcing `aud` to the client id would mint tokens the operator's own
				// API rejects, since its audience check never names the client.
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "read" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: {
						...basicAuthClient,
						allowedAudiences: ["https://api.example.com"],
					},
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("https://api.example.com");
				// azp still names who asked, not what the token is for.
				expect(decoded.azp).toBe("first-party-app");
			});

			it("returns 401 when the request was not client-authenticated", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "admin:*" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(401);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_client");
			});

			// #295 pinned "the client repository is not consulted" with a spy on
			// an injected mock. #331 removed the dependency from the factory
			// signature entirely, so the type system now enforces what that
			// test observed and the pin is retired with the parameter.
		});

		it("does not return sessionMutation", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true },
				issuer: "localhost",
				metadata: {},
				authenticatedClient: AUTH_CLIENT,
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});
});

// ---------------------------------------------------------------------------
// #297 — the email-verified gate on the session grant
// ---------------------------------------------------------------------------

describe("createSessionGrant — email-verified gate (#297)", () => {
	const gatedConfig = {
		...(mockConfig as unknown as Record<string, unknown>),
		oauth: {
			...(mockConfig as unknown as { oauth: Record<string, unknown> }).oauth,
			requireEmailVerified: true,
		},
	} as unknown as GrantDependencies["config"];

	const runWith = async (
		config: GrantDependencies["config"],
		user: Record<string, unknown> | undefined,
	) => {
		const handler = createSessionGrant(makeDeps({ config }));
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: true, ...(user ? { user } : {}) },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: AUTH_CLIENT,
		} as GrantContext);
		return result;
	};

	it("refuses when the gate is on and the Store published no verification", async () => {
		// This grant mints straight from the browser session, so gating only
		// /authorize would leave a deployment believing it had a gate.
		const result = await runWith(gatedConfig, { id: "u1" });
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("refuses on an explicit false", async () => {
		const result = await runWith(gatedConfig, { id: "u1", emailVerified: false });
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("admits when the Store published true", async () => {
		const result = await runWith(gatedConfig, { id: "u1", emailVerified: true });
		expect(result.status).toBe(200);
	});

	it("is inert when the gate is off", async () => {
		const result = await runWith(mockConfig, { id: "u1" });
		expect(result.status).toBe(200);
	});
});
