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
	type AppConfig,
	type AuditEvent,
	type AuditSinkBase,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type FederationTokenStoreBase,
	type GrantHandler,
	GrantRegistry,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express, { type Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const mockConfig = {
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const fullConfig = {
	oauth: { jwt: { issuer: "https://issuer.example" } },
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const TEST_CLIENT_ID = "client1";
const TEST_CLIENT_SECRET = "secret1";
const TEST_BASIC_AUTH = `Basic ${Buffer.from(`${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}`).toString("base64")}`;

const integrationClientRepo: ClientRepository = {
	findById: async (clientId) =>
		clientId === TEST_CLIENT_ID
			? {
					clientId: TEST_CLIENT_ID,
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: [],
					allowedScopes: [],
				}
			: null,
	authenticate: async (clientId, secret) =>
		clientId === TEST_CLIENT_ID && secret === TEST_CLIENT_SECRET
			? {
					clientId: TEST_CLIENT_ID,
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: [],
					allowedScopes: [],
				}
			: null,
};

const integrationCodeRepo: CodeRepository = {
	createCode: async () => ({
		code: "code-x",
		client_id: TEST_CLIENT_ID,
		redirect_uri: "https://rp.example/cb",
	}),
	getByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const mockExpress = {
	Router: () =>
		({
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn().mockReturnThis(),
		}) as unknown as Router,
	json: () => vi.fn(),
	urlencoded: () => vi.fn(),
};

function createTrackingExpress() {
	const calls: { get: unknown[][]; post: unknown[][]; use: unknown[][] } = {
		get: [],
		post: [],
		use: [],
	};
	const expressLike = {
		Router: () => {
			const router = {
				use: vi.fn((...args: unknown[]) => {
					calls.use.push(args);
					return router;
				}),
				get: vi.fn((...args: unknown[]) => {
					calls.get.push(args);
					return router;
				}),
				post: vi.fn((...args: unknown[]) => {
					calls.post.push(args);
					return router;
				}),
			} as unknown as Router;
			return router;
		},
		json: () => vi.fn(),
		urlencoded: () => vi.fn(),
	};
	return { calls, expressLike };
}

describe("createOAuthRouter", () => {
	it("returns a router", async () => {
		const result = await createOAuthRouter(mockExpress, {
			registry: new GrantRegistry(),
			config: mockConfig,
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret"),
		});

		expect(result.router).toBeDefined();
	});

	it("applies rate limit middleware to POST /introspect", async () => {
		const postCalls: unknown[][] = [];
		const router = {
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn((...args: unknown[]) => {
				postCalls.push(args);
				return router;
			}),
		} as unknown as Router;

		const trackingExpress = {
			Router: () => router,
			json: () => vi.fn(),
			urlencoded: () => vi.fn(),
		};

		await createOAuthRouter(trackingExpress, {
			registry: new GrantRegistry(),
			config: mockConfig,
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret"),
		});

		// Find the /introspect POST registration
		const introspectCall = postCalls.find((args) => args[0] === "/introspect");
		expect(introspectCall).toBeDefined();
		if (!introspectCall) return;

		// Should have at least 3 args: path, rate-limit middleware, auth middleware, handler
		// (path + tokenRateLimit + authMiddleware + handler = 4 args minimum)
		expect(introspectCall.length).toBeGreaterThanOrEqual(3);

		// The second arg (index 1) is the rate-limit middleware — it must be a function
		expect(typeof introspectCall[1]).toBe("function");
	});

	it("applies rate limit middleware to POST /token", async () => {
		const { calls, expressLike } = createTrackingExpress();

		await createOAuthRouter(expressLike, {
			registry: new GrantRegistry(),
			config: mockConfig,
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret"),
		});

		const tokenCall = calls.post.find((args) => args[0] === "/token");
		expect(tokenCall).toBeDefined();
		if (!tokenCall) return;
		expect(tokenCall.length).toBeGreaterThanOrEqual(4);
		expect(typeof tokenCall[1]).toBe("function");
	});

	it("registers authorize and UserInfo GET/POST routes", async () => {
		const { calls, expressLike } = createTrackingExpress();

		await createOAuthRouter(expressLike, {
			registry: new GrantRegistry(),
			config: mockConfig,
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret"),
		});

		expect(calls.get.some((args) => args[0] === "/authorize")).toBe(true);
		expect(calls.get.some((args) => args[0] === "/userinfo")).toBe(true);
		expect(calls.post.some((args) => args[0] === "/userinfo")).toBe(true);
	});

	it("registers GET /logout when logout dependencies are wired", async () => {
		const { calls, expressLike } = createTrackingExpress();

		await createOAuthRouter(expressLike, {
			registry: new GrantRegistry(),
			config: fullConfig,
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret"),
			userSessionStore: {} as UserSessionStore,
			sessionRPRegistry: {} as SessionRPRegistry,
			sessionFamilyIndex: {} as SessionFamilyIndex,
			sessionFederationIndex: {} as SessionFederationIndex,
			federationTokenStore: {} as FederationTokenStoreBase,
			refreshTokenFamilyRevocation: {} as RefreshTokenFamilyRevocation,
		});

		expect(calls.get.some((args) => args[0] === "/logout")).toBe(true);
		expect(calls.post.some((args) => args[0] === "/logout")).toBe(true);
	});

	// D-6 (v0.5.1) integration coverage: exercise the full /oauth/token pipeline
	// end-to-end via supertest + a real express app. The mocked-router tests
	// above only verify wiring; these tests cover the success-path token
	// response, audit emit, and the 401 → `WWW-Authenticate: Bearer` branch.
	describe("D-6 /oauth/token integration", () => {
		async function buildApp(opts: {
			grantHandler: GrantHandler;
			grantType: string;
			auditSink?: AuditSinkBase;
		}) {
			const app = express();
			app.set("trust proxy", 1);
			app.use(express.json());
			app.use(express.urlencoded({ extended: false }));
			const registry = new GrantRegistry();
			registry.register(opts.grantType, opts.grantHandler);
			const { router } = await createOAuthRouter(express, {
				registry,
				config: fullConfig,
				clientRepository: integrationClientRepo,
				codeRepository: integrationCodeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				auditSink: opts.auditSink,
			});
			app.use("/oauth", router);
			return app;
		}

		it("success path: returns 200 + tokens + Cache-Control no-store + audit", async () => {
			const events: AuditEvent[] = [];
			const auditSink: AuditSinkBase = {
				kind: "spy",
				record: async (e) => {
					events.push(e);
				},
			};
			const stubGrant: GrantHandler = {
				handle: async (_ctx) => ({
					result: {
						status: 200,
						tokens: { access_token: "at.x.y", token_type: "Bearer", expires_in: 300 },
					},
				}),
			};
			const app = await buildApp({ grantHandler: stubGrant, grantType: "stub", auditSink });
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "stub" });

			expect(res.status).toBe(200);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
			expect(res.body.access_token).toBe("at.x.y");
			// `clientId` in the audit event uses the authenticated identity, not body.
			await new Promise((r) => setImmediate(r));
			const issuedEvent = events.find((e) => e.type === "token.issued");
			expect(issuedEvent).toBeDefined();
			expect(issuedEvent?.clientId).toBe(TEST_CLIENT_ID);
		});

		it("error path with errorDescription + 401 does NOT inject WWW-Authenticate (Copilot review)", async () => {
			// A grant handler returning status 401 (e.g. ctx.authenticatedClient
			// missing in a custom wiring) does NOT cause a `WWW-Authenticate:
			// Bearer` challenge to be set on the token endpoint — RFC 6750 §3
			// applies to protected resource servers, not authorization endpoints,
			// and clobbering `clientAuthMw`'s upstream `WWW-Authenticate: Basic`
			// challenge on auth failures would mislead callers into retrying with
			// the wrong scheme.
			const events: AuditEvent[] = [];
			const auditSink: AuditSinkBase = {
				kind: "spy",
				record: async (e) => {
					events.push(e);
				},
			};
			const stubGrant: GrantHandler = {
				handle: async (_ctx) => ({
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "stub denied",
					},
				}),
			};
			const app = await buildApp({ grantHandler: stubGrant, grantType: "stub", auditSink });
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "stub" });

			expect(res.status).toBe(401);
			// No WWW-Authenticate set by the route — clientAuthMw passed, the
			// 401 came from the handler itself, and we do not impose Bearer here.
			expect(res.headers["www-authenticate"]).toBeUndefined();
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("stub denied");
			await new Promise((r) => setImmediate(r));
			const failEvent = events.find((e) => e.type === "token.issued.failure");
			expect(failEvent).toBeDefined();
			expect(failEvent?.clientId).toBe(TEST_CLIENT_ID);
		});

		it("missing grant_type: returns 400 unsupported_grant_type + audit failure", async () => {
			// Covers the early `if (typeof grant_type !== "string" ...)` branch.
			const events: AuditEvent[] = [];
			const auditSink: AuditSinkBase = {
				kind: "spy",
				record: async (e) => {
					events.push(e);
				},
			};
			const stubGrant: GrantHandler = {
				handle: async () => ({
					result: { status: 200, tokens: { access_token: "x", token_type: "Bearer" } },
				}),
			};
			const app = await buildApp({ grantHandler: stubGrant, grantType: "stub", auditSink });
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({}); // no grant_type
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
			await new Promise((r) => setImmediate(r));
			expect(events.find((e) => e.type === "token.issued.failure")).toBeDefined();
		});

		it("sessionMutation.clear and .set: route propagates both to req.session", async () => {
			// Grants returning `sessionMutation` (e.g., session-bound flows that
			// need to clear ephemeral state and write a new sid) rely on the
			// /token route applying both `clear` and `set` on the request session
			// before responding. Without this propagation, downstream routes would
			// observe stale session state.
			let observedSession: Record<string, unknown> | undefined;
			const sessionGrant: GrantHandler = {
				handle: async () => ({
					result: {
						status: 200,
						tokens: { access_token: "at.x", token_type: "Bearer", expires_in: 60 },
					},
					sessionMutation: {
						clear: ["clearMe"],
						set: { setMe: "newValue" },
					},
				}),
			};

			const app = express();
			app.set("trust proxy", 1);
			app.use(express.json());
			app.use(express.urlencoded({ extended: false }));
			app.use((req, _res, next) => {
				const session: Record<string, unknown> = {
					clearMe: "old",
					existingKey: "stays",
				};
				(req as unknown as { session: Record<string, unknown> }).session = session;
				observedSession = session;
				next();
			});

			const registry = new GrantRegistry();
			registry.register("session-mutating", sessionGrant);
			const { router } = await createOAuthRouter(express, {
				registry,
				config: fullConfig,
				clientRepository: integrationClientRepo,
				codeRepository: integrationCodeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			});
			app.use("/oauth", router);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "session-mutating" });

			expect(res.status).toBe(200);
			// `clear` sets the property to undefined (route does not delete).
			expect(observedSession?.clearMe).toBeUndefined();
			expect(observedSession?.setMe).toBe("newValue");
			expect(observedSession?.existingKey).toBe("stays");
		});
	});

	describe("D-6 /oauth/introspect non-Bearer fallback", () => {
		// When /introspect is called WITHOUT a `Bearer` Authorization header, the
		// route hands off to `introspectClientAuthMw` (RFC 7662 §2.1) — the same
		// confidential-client auth used for /token. This exercises the fallback
		// branch + the post-auth body-token-missing branch (200 { active: false }).
		async function buildIntrospectApp() {
			const app = express();
			app.set("trust proxy", 1);
			app.use(express.json());
			app.use(express.urlencoded({ extended: false }));
			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: fullConfig,
				clientRepository: integrationClientRepo,
				codeRepository: integrationCodeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			});
			app.use("/oauth", router);
			return app;
		}

		it("Basic auth + missing token returns 200 { active: false } via client-auth fallback", async () => {
			const app = await buildIntrospectApp();
			const res = await request(app)
				.post("/oauth/introspect")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({}); // no token field
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ active: false });
		});
	});
});
