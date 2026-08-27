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
	type AuditSink,
	type ClientRepository,
	type Code,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantPolicyHook,
	type Logger,
	type RateLimiter,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

// OR-5: `checkRateLimit` reads `config.rateLimit.failMode` in the catch
// path. The mock config carries `failMode: "open"` to exercise the
// default behavior; closed-mode tests below override `rateLimit` per-test.
const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		// These tests target audit / grantPolicy / rateLimit hooks at the
		// authorize endpoint and do not request openid. oidcMode defaults to
		// "oidc-required" with an issuer configured, which would reject every
		// request as invalid_scope before the hook paths run. Opt out with
		// dual mode so the hook behavior is the only variable under test.
		oidcMode: "dual",
	},
	rateLimit: {
		login: { windowMs: 60_000, limit: 100 },
		failMode: "open",
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

// D-6 (v0.5.1): every hit on /oauth/token now traverses `clientAuthMw` before
// the registered grant handler runs. The mock client repository returns a
// fixed "client1" / "secret1" pair so route-level integration tests can
// authenticate by sending `Authorization: ${TEST_BASIC_AUTH}` and exercise the
// rate-limit / audit / grant-policy paths under the new flow.
const TEST_CLIENT_ID = "client1";
const TEST_CLIENT_SECRET = "secret1";
const TEST_BASIC_AUTH = `Basic ${Buffer.from(`${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}`).toString("base64")}`;

const mockClientRepository: ClientRepository = {
	findById: async (clientId) =>
		clientId === TEST_CLIENT_ID
			? {
					clientId: TEST_CLIENT_ID,
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: ["https://rp.example/cb"],
					firstParty: true,
					allowedScopes: [],
				}
			: null,
	authenticate: async (clientId, secret) =>
		clientId === TEST_CLIENT_ID && secret === TEST_CLIENT_SECRET
			? {
					clientId: TEST_CLIENT_ID,
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: ["https://rp.example/cb"],
					firstParty: true,
					allowedScopes: [],
				}
			: null,
};

const mockCodeRepository: CodeRepository = {
	// D-1: Code requires client_id + redirect_uri.
	createCode: async () => ({
		code: "test-code",
		client_id: "client1",
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

function createStubRateLimiter(
	onCheck: (key: string) => { allowed: boolean; reason?: string; resetAt?: Date },
): RateLimiter {
	return {
		kind: "stub",
		async check(key) {
			return onCheck(key);
		},
	};
}

function createSpyAuditSink(): { sink: AuditSink; events: AuditEvent[] } {
	const events: AuditEvent[] = [];
	return {
		events,
		sink: {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		},
	};
}

async function buildApp(overrides: {
	rateLimiter?: RateLimiter;
	auditSink?: AuditSink;
	logger?: Logger;
	config?: AppConfig;
}) {
	const app = express();
	// Ensure req.ip is consistently populated so the RateLimiter hook sees it
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: overrides.config ?? mockConfig,
		clientRepository: mockClientRepository,
		codeRepository: mockCodeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...overrides,
	});

	app.use("/oauth", router);
	return app;
}

describe("oauth routes — TODO-C hooks (Phase 1)", () => {
	describe("rateLimiter hook", () => {
		it("returns 429 rate_limited when rateLimiter denies /oauth/token", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({
					allowed: false,
					reason: "limit:token",
					resetAt: new Date(Date.now() + 30_000),
				})),
			});

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "password" });

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			// AS-2: 429 body migrated from `{reason}` to RFC 6749 §5.2 `{error_description}`.
			expect(res.body.error_description).toBe("limit:token");
			expect(res.body).not.toHaveProperty("reason");
			const retryAfter = Number(res.headers["retry-after"]);
			expect(retryAfter).toBeGreaterThanOrEqual(29);
		});

		it("sets Retry-After header from decision.resetAt", async () => {
			const resetAt = new Date(Date.now() + 60_000);
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({
					allowed: false,
					reason: "limit:token",
					resetAt,
				})),
			});

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "refresh_token" });

			expect(res.status).toBe(429);
			expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
		});

		it("returns 429 rate_limited when rateLimiter denies /oauth/introspect", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter((key) =>
					key.startsWith("introspect")
						? { allowed: false, reason: "limit:introspect" }
						: { allowed: true },
				),
			});

			const res = await request(app).post("/oauth/introspect").send({ token: "any" });

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			// AS-2: same envelope on this 429 path. Lock in the contract on the
			// introspect surface too, otherwise drift on this branch goes silent.
			expect(res.body.error_description).toBe("limit:introspect");
			expect(res.body).not.toHaveProperty("reason");
		});

		it("fails open when rateLimiter.check throws and emits rate_limit.unavailable audit (CP-6)", async () => {
			const { sink, events } = createSpyAuditSink();
			const app = await buildApp({
				rateLimiter: {
					kind: "broken",
					async check() {
						throw new Error("redis down");
					},
				},
				auditSink: sink,
			});

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "unsupported_type_xyz" });

			// 400 unsupported_grant_type — request was allowed through (fail-open)
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
			// Yield microtasks so the fire-and-forget audit emit settles
			await new Promise((r) => setImmediate(r));
			const ev = events.find((e) => e.type === "rate_limit.unavailable");
			expect(ev).toBeDefined();
			expect((ev?.details as { error?: string } | undefined)?.error).toContain("redis down");
		});

		// OR-5: fail-mode policy + logger emission. Pre-OR-5 the limiter
		// outage was silent (audit sink was the only path, and a Redis-backed
		// audit sink also drops during the same outage). The new logger
		// emission ensures operators see the outage regardless of audit sink
		// status; `failMode = "closed"` adds 503 enforcement on top.
		describe("OR-5: failMode policy + logger emission", () => {
			const makeMockLogger = (): Logger & { error: ReturnType<typeof vi.fn> } => ({
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
			});

			const brokenRateLimiter: RateLimiter = {
				kind: "broken",
				async check() {
					throw new Error("redis down");
				},
			};

			it("failMode='open' + limiter throws → request allowed + logger.error('rate_limiter_failed_open')", async () => {
				const logger = makeMockLogger();
				const app = await buildApp({
					rateLimiter: brokenRateLimiter,
					logger,
					// mockConfig already has failMode: "open"
				});

				const res = await request(app)
					.post("/oauth/token")
					.set("Authorization", TEST_BASIC_AUTH)
					.send({ grant_type: "unsupported_type_xyz" });

				// fail-open: 400 unsupported_grant_type from the route, NOT 503
				expect(res.status).toBe(400);
				expect(logger.error).toHaveBeenCalledWith(
					expect.objectContaining({
						error: expect.stringContaining("redis down"),
						mode: "open",
						tag: "token",
					}),
					"rate_limiter_failed_open",
				);
			});

			it("failMode='closed' + limiter throws → 503 service_unavailable + logger.error('rate_limiter_failed_closed')", async () => {
				const logger = makeMockLogger();
				const closedConfig = {
					...(mockConfig as unknown as Record<string, unknown>),
					rateLimit: {
						login: { windowMs: 60_000, limit: 100 },
						failMode: "closed",
					},
				} as unknown as AppConfig;
				const app = await buildApp({
					rateLimiter: brokenRateLimiter,
					logger,
					config: closedConfig,
				});

				const res = await request(app)
					.post("/oauth/token")
					.set("Authorization", TEST_BASIC_AUTH)
					.send({ grant_type: "unsupported_type_xyz" });

				expect(res.status).toBe(503);
				expect(res.body.error).toBe("service_unavailable");
				expect(logger.error).toHaveBeenCalledWith(
					expect.objectContaining({
						error: expect.stringContaining("redis down"),
						mode: "closed",
						tag: "token",
					}),
					"rate_limiter_failed_closed",
				);
			});

			it("failMode='open' + limiter succeeds and allows → no logger.error call (success path is silent)", async () => {
				const logger = makeMockLogger();
				const app = await buildApp({
					rateLimiter: createStubRateLimiter(() => ({ allowed: true })),
					logger,
				});

				const res = await request(app)
					.post("/oauth/token")
					.set("Authorization", TEST_BASIC_AUTH)
					.send({ grant_type: "unsupported_type_xyz" });

				expect(res.status).toBe(400); // unsupported_grant_type, not 503
				expect(logger.error).not.toHaveBeenCalledWith(
					expect.anything(),
					expect.stringMatching(/^rate_limiter_failed_/),
				);
			});

			it("failMode='closed' + limiter succeeds and allows → no logger.error call (failMode only affects error path)", async () => {
				const logger = makeMockLogger();
				const closedConfig = {
					...(mockConfig as unknown as Record<string, unknown>),
					rateLimit: {
						login: { windowMs: 60_000, limit: 100 },
						failMode: "closed",
					},
				} as unknown as AppConfig;
				const app = await buildApp({
					rateLimiter: createStubRateLimiter(() => ({ allowed: true })),
					logger,
					config: closedConfig,
				});

				const res = await request(app)
					.post("/oauth/token")
					.set("Authorization", TEST_BASIC_AUTH)
					.send({ grant_type: "unsupported_type_xyz" });

				expect(res.status).toBe(400); // unsupported_grant_type, not 503
				expect(logger.error).not.toHaveBeenCalledWith(
					expect.anything(),
					expect.stringMatching(/^rate_limiter_failed_/),
				);
			});
		});

		it("does not block requests when rateLimiter allows", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({ allowed: true })),
			});

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "unsupported_type_xyz" });

			// Not 429 — rate limiter allowed; 400 from unsupported_grant_type
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
		});

		it("normalized ip passed into check ctx matches key derivation (CP-10)", async () => {
			let observedKey: string | undefined;
			let observedCtxIp: string | undefined;
			const rateLimiter: RateLimiter = {
				kind: "capture",
				async check(key, ctx) {
					observedKey = key;
					observedCtxIp = ctx?.ip;
					return { allowed: true };
				},
			};
			const app = await buildApp({ rateLimiter });
			await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "unsupported_xyz" });
			expect(observedKey).toBeDefined();
			// Extract ip portion from key "token:ip:<ip>"
			const keyIp = observedKey?.split(":").slice(2).join(":");
			expect(observedCtxIp).toBe(keyIp);
		});
	});

	describe("auditSink hook", () => {
		it("emits token.issued.failure audit event for unsupported grant_type", async () => {
			const { sink, events } = createSpyAuditSink();
			const app = await buildApp({ auditSink: sink });

			await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "unsupported_xyz" });

			expect(events.length).toBeGreaterThanOrEqual(1);
			const ev = events.find((e) => e.type === "token.issued.failure");
			expect(ev).toBeDefined();
		});

		it("does not throw when auditSink is undefined (no-op)", async () => {
			const app = await buildApp({});

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.send({ grant_type: "unsupported_xyz" });

			expect(res.status).toBe(400);
		});

		it("login.success audit event carries subject from session.user.id (I-2)", async () => {
			const { sink, events } = createSpyAuditSink();
			const app = express();
			app.set("trust proxy", 1);
			app.use(express.json());
			app.use(express.urlencoded({ extended: false }));

			// Inline session middleware substitute — minimal surface needed by routes
			app.use((req, _res, next) => {
				(req as unknown as { session: Record<string, unknown> }).session = {
					isAuthenticated: true,
					user: { id: "user-42" },
				};
				next();
			});

			const clientRepo: ClientRepository = {
				findById: async () => ({
					clientId: "client-42",
					allowedRedirectUris: ["https://example.test/cb"],
					firstParty: true,
					allowedScopes: ["read"],
				}),
				authenticate: async () => null,
			};
			const codeRepo: CodeRepository = {
				// D-1: Code requires client_id + redirect_uri.
				createCode: async () => ({
					code: "auth-code-1",
					client_id: "client1",
					redirect_uri: "https://rp.example/cb",
				}),
				findByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				auditSink: sink,
			});
			app.use("/oauth", router);

			await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-42",
				redirect_uri: "https://example.test/cb",
			});

			const ev = events.find((e) => e.type === "login.success");
			expect(ev).toBeDefined();
			expect(ev?.subject).toBe("user-42");
		});
	});

	describe("grantPolicy hook (C-2)", () => {
		function buildAuthorizeApp(opts: {
			grantPolicy?: GrantPolicyHook;
			captureCode?: (params: Parameters<CodeRepository["createCode"]>[0]) => void;
			allowedScopes?: string[];
		}) {
			const app = express();
			app.set("trust proxy", 1);
			app.use(express.json());
			app.use(express.urlencoded({ extended: false }));
			app.use((req, _res, next) => {
				(req as unknown as { session: Record<string, unknown> }).session = {
					isAuthenticated: true,
					user: { id: "user-1" },
				};
				next();
			});

			const clientRepo: ClientRepository = {
				findById: async () => ({
					clientId: "client-1",
					allowedRedirectUris: ["https://example.test/cb"],
					firstParty: true,
					allowedScopes: opts.allowedScopes ?? ["read", "write"],
				}),
				authenticate: async () => null,
			};
			const codeRepo: CodeRepository = {
				createCode: async (params) => {
					opts.captureCode?.(params);
					// D-1: echo identity fields from params so the returned Code
					// satisfies the new required shape.
					return {
						code: "code-1",
						client_id: params.client_id,
						redirect_uri: params.redirect_uri,
						grantedScope: params.grantedScope,
						grantedAudience: params.grantedAudience,
					};
				},
				findByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			};

			return { app, clientRepo, codeRepo };
		}

		it("evaluates grantPolicy at /authorize and persists narrowed scope on Code", async () => {
			let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({
				captureCode: (p) => {
					captured = p;
				},
			});
			const grantPolicy: GrantPolicyHook = {
				kind: "spy",
				async evaluate(request) {
					expect(request.grantType).toBe("authorization_code");
					expect(request.clientId).toBe("client-1");
					expect(request.subject).toBe("user-1");
					return {
						outcome: "allow",
						grantedScope: ["read"],
						grantedAudience: ["aud-1"],
					};
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read write",
			});

			expect(captured).toBeDefined();
			expect(captured?.grantedScope).toEqual(["read"]);
			expect(captured?.grantedAudience).toEqual(["aud-1"]);
		});

		it("redirects with error when grantPolicy denies at /authorize", async () => {
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({});
			const grantPolicy: GrantPolicyHook = {
				kind: "deny",
				async evaluate() {
					return {
						outcome: "deny",
						error: "access_denied",
						errorDescription: "policy refused",
					};
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			const res = await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			expect(res.status).toBe(302);
			expect(res.headers.location).toContain("error=access_denied");
			expect(res.headers.location).toContain("policy");
		});

		it("persists undefined scope when no grantPolicy is configured (falls back to client-filtered)", async () => {
			let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({
				captureCode: (p) => {
					captured = p;
				},
			});

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			});
			app.use("/oauth", router);

			await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			// Without grantPolicy, Code.grantedScope is the requested-intersected-allowed set
			expect(captured?.grantedScope).toEqual(["read"]);
			expect(captured?.grantedAudience).toBeUndefined();
		});

		it("rejects with invalid_scope when grantPolicy returns scopes outside client allowance (CP-13)", async () => {
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({
				allowedScopes: ["read"],
			});
			const grantPolicy: GrantPolicyHook = {
				kind: "escalating",
				async evaluate() {
					// Policy attempts to grant a scope the client isn't allowed to request.
					return { outcome: "allow", grantedScope: ["read", "admin"] };
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			const res = await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			expect(res.status).toBe(302);
			expect(res.headers.location).toContain("error=invalid_scope");
			expect(res.headers.location).toContain("admin");
		});

		it("redirects temporarily_unavailable when grantPolicy throws at /authorize (CP-18)", async () => {
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({});
			const grantPolicy: GrantPolicyHook = {
				kind: "throwing",
				async evaluate() {
					throw new Error("policy backend down");
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			const res = await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			expect(res.status).toBe(302);
			expect(res.headers.location).toContain("error=temporarily_unavailable");
		});

		it("persists undefined grantedScope on Code when policy narrows to empty (CP-14)", async () => {
			let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({
				captureCode: (p) => {
					captured = p;
				},
			});
			const grantPolicy: GrantPolicyHook = {
				kind: "empty",
				async evaluate() {
					return { outcome: "allow", grantedScope: [] };
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			await request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			expect(captured?.grantedScope).toBeUndefined();
		});

		it("authorization grant reads Code.grantedScope (not session.granted_scopes)", async () => {
			// Simulate that /authorize ran earlier and persisted ["read"] on the Code,
			// but the session got tampered to ["write"]. Code must win.
			const persistedCode: Code = {
				code: "code-xyz",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				grantedScope: ["read"],
				sid: "test-sid-1",
			};
			const codeRepo: CodeRepository = {
				createCode: async () => persistedCode,
				findByCode: async () => persistedCode,
				consumeByCode: async () => persistedCode,
				removeByCode: async () => {},
			};
			const { createAuthorizationGrant } = await import("#/grants/authorization.mjs");
			const deps = {
				config: mockConfig,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				codeRepository: codeRepo,
				clientRepository: {
					findById: async () => null,
					authenticate: async () => null,
				},
			};
			const handler = createAuthorizationGrant(deps);

			const { result } = await handler.handle({
				body: {
					code: "code-xyz",
					client_id: "client-1",
					redirect_uri: "https://example.test/cb",
				},
				session: {
					code: "code-xyz",
					code_client_id: "client-1",
					granted_scopes: ["write"],
					user: { id: "u1" },
				},
				issuer: "https://auth.example",
				metadata: {},
				authenticatedClient: {
					clientId: "client-1",
					tokenEndpointAuthMethod: "client_secret_basic",
				},
			});

			if (!("tokens" in result)) throw new Error("expected tokens");
			const { decodeJwt } = await import("jose");
			const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(decoded.scope).toBe("read");
		});

		it("passes trusted config.oauth.jwt.issuer (not Host header) to grantPolicy (CP-11)", async () => {
			const { app, clientRepo, codeRepo } = buildAuthorizeApp({});
			let observedIssuer: string | undefined;
			const grantPolicy: GrantPolicyHook = {
				kind: "spy",
				async evaluate(_req, ctx) {
					observedIssuer = ctx.issuer;
					return { outcome: "allow" };
				},
			};

			const { router } = await createOAuthRouter(express, {
				registry: new GrantRegistry(),
				config: mockConfig,
				clientRepository: clientRepo,
				codeRepository: codeRepo,
				keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				grantPolicy,
			});
			app.use("/oauth", router);

			// Send a spoofed Host header to confirm the issuer passed to policy is
			// the configured one, not the attacker-controlled header.
			await request(app).get("/oauth/authorize").set("Host", "evil.example").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				scope: "read",
			});

			expect(observedIssuer).toBe("https://auth.example");
			expect(observedIssuer).not.toContain("evil.example");
		});
	});
});
