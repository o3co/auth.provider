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
	type Code,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantPolicyHookBase,
	GrantRegistry,
	type RateLimiterBase,
} from "@o3co/auth-provider-core";
import express from "express";
import type { PassportStatic } from "passport";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const mockPassport = {
	authenticate: () => (_req: unknown, _res: unknown, next: () => void) => next(),
} as unknown as PassportStatic;

const mockClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const mockCodeRepository: CodeRepository = {
	createCode: async () => ({ code: "test-code" }),
	getByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

function createStubRateLimiter(
	onCheck: (key: string) => { allowed: boolean; reason?: string; resetAt?: Date },
): RateLimiterBase {
	return {
		kind: "stub",
		async check(key) {
			return onCheck(key);
		},
	};
}

function createSpyAuditSink(): { sink: AuditSinkBase; events: AuditEvent[] } {
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

async function buildApp(overrides: { rateLimiter?: RateLimiterBase; auditSink?: AuditSinkBase }) {
	const app = express();
	// Ensure req.ip is consistently populated so the RateLimiter hook sees it
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	const { router } = await createOAuthRouter(express, {
		passport: mockPassport,
		registry: new GrantRegistry(),
		config: mockConfig,
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

			const res = await request(app).post("/oauth/token").send({ grant_type: "password" });

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			expect(res.body.reason).toBe("limit:token");
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

			const res = await request(app).post("/oauth/token").send({ grant_type: "refresh_token" });

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

		it("does not block requests when rateLimiter allows", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({ allowed: true })),
			});

			const res = await request(app)
				.post("/oauth/token")
				.send({ grant_type: "unsupported_type_xyz" });

			// Not 429 — rate limiter allowed; 400 from unsupported_grant_type
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
		});
	});

	describe("auditSink hook", () => {
		it("emits token.issued.failure audit event for unsupported grant_type", async () => {
			const { sink, events } = createSpyAuditSink();
			const app = await buildApp({ auditSink: sink });

			await request(app).post("/oauth/token").send({ grant_type: "unsupported_xyz" });

			expect(events.length).toBeGreaterThanOrEqual(1);
			const ev = events.find((e) => e.type === "token.issued.failure");
			expect(ev).toBeDefined();
		});

		it("does not throw when auditSink is undefined (no-op)", async () => {
			const app = await buildApp({});

			const res = await request(app).post("/oauth/token").send({ grant_type: "unsupported_xyz" });

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
					allowedScopes: ["read"],
				}),
				authenticate: async () => null,
			};
			const codeRepo: CodeRepository = {
				createCode: async () => ({ code: "auth-code-1" }),
				getByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			};

			const { router } = await createOAuthRouter(express, {
				passport: mockPassport,
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
			grantPolicy?: GrantPolicyHookBase;
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
					allowedScopes: opts.allowedScopes ?? ["read", "write"],
				}),
				authenticate: async () => null,
			};
			const codeRepo: CodeRepository = {
				createCode: async (params) => {
					opts.captureCode?.(params);
					return {
						code: "code-1",
						redirect_uri: params.redirect_uri,
						grantedScope: params.grantedScope,
						grantedAudience: params.grantedAudience,
					};
				},
				getByCode: async () => null,
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
			const grantPolicy: GrantPolicyHookBase = {
				kind: "spy",
				async evaluate(request) {
					expect(request.grantType).toBe("authorization");
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
				passport: mockPassport,
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
			const grantPolicy: GrantPolicyHookBase = {
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
				passport: mockPassport,
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
				passport: mockPassport,
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

		it("authorization grant reads Code.grantedScope (not session.granted_scopes)", async () => {
			// Simulate that /authorize ran earlier and persisted ["read"] on the Code,
			// but the session got tampered to ["write"]. Code must win.
			const persistedCode: Code = {
				code: "code-xyz",
				redirect_uri: "https://example.test/cb",
				grantedScope: ["read"],
			};
			const codeRepo: CodeRepository = {
				createCode: async () => persistedCode,
				getByCode: async () => persistedCode,
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
			});

			if (!("tokens" in result)) throw new Error("expected tokens");
			const { decodeJwt } = await import("jose");
			const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(decoded.scope).toBe("read");
		});
	});
});
