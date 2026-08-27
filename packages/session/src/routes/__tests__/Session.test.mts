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

import type { AppConfig, UserRepository, UserSessionStore } from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createCsrfProtection } from "#/csrf.mjs";
import { createRouter } from "#/routes/Session.mjs";

/** Minimal AppConfig stub */
const stubConfig: AppConfig = {
	cors: { allowedOrigins: [] },
	rateLimit: {
		login: { windowMs: 60_000, limit: 100 },
	},
	session: {
		secret: "test-session-secret",
		name: "auth.session",
		secure: false,
		sameSite: "lax",
		domain: null,
	},
} as unknown as AppConfig;

/**
 * A double-submit pair minted from the same secret and cookie name the router
 * derives from `stubConfig`. Since #272 the state-changing session routes
 * reject a request carrying neither an origin signal nor a token, and
 * `supertest` sends no `Origin` — which is exactly the header-less API client
 * the token arm exists to keep working.
 */
const csrf = createCsrfProtection({
	secret: "test-session-secret",
	cookieName: "auth.session.csrf",
});
const csrfToken = csrf.mint();

const withCsrf = (test: request.Test): request.Test =>
	test.set("Cookie", `${csrf.cookieName}=${csrfToken}`).set(csrf.headerName, csrfToken);

const loginRequest = (app: express.Express): request.Test =>
	withCsrf(request(app).post("/session/login"));

const logoutRequest = (app: express.Express): request.Test =>
	withCsrf(request(app).post("/session/logout"));

/** In-memory UserSessionStore fake that exposes created sessions for assertions */
function makeUserSessionStore(): UserSessionStore & { sessions: unknown[] } {
	const sessions: unknown[] = [];
	return {
		kind: "memory",
		sessions,
		async create(input) {
			sessions.push(structuredClone(input));
		},
		async get() {
			return null;
		},
		async delete() {},
	} as UserSessionStore & { sessions: unknown[] };
}

/**
 * Build a test express app with the Session router mounted at "/session".
 *
 * userRepository.authenticate controls the login outcome:
 * - resolves to a User object → successful login
 * - resolves to null → invalid credentials (401)
 * - rejects with an Error → authentication error (500)
 *
 * Returns `capturedSession`: a ref populated by a post-router middleware so
 * tests can assert on `req.session` fields (e.g. `sid`) after a response.
 */
function buildApp(
	opts: {
		userRepository?: UserRepository;
		userSessionStore?: UserSessionStore;
		sessionTtlMs?: number;
		regenerateError?: Error;
		destroyError?: Error;
		config?: AppConfig;
	} = {},
) {
	const {
		userRepository = {
			authenticate: vi.fn().mockResolvedValue({
				id: "u-1",
				username: "alice",
				email: "alice@example.com",
			}),
			authenticateByToken: vi.fn(),
		} as unknown as UserRepository,
		userSessionStore,
		sessionTtlMs,
		regenerateError,
		destroyError,
		config = stubConfig,
	} = opts;

	const app = express();

	// Minimal express-session stub so req.session.regenerate / destroy / save work.
	// regenerateError/destroyError opt-ins simulate session-store failures so tests
	// can drive the AS-1 500 server_error envelope paths.
	app.use((req, _res, next) => {
		const sessionData: Record<string, unknown> = {};
		(req as unknown as { session: Record<string, unknown> }).session = {
			...sessionData,
			regenerate(cb: (err: Error | null) => void) {
				if (regenerateError) {
					cb(regenerateError);
					return;
				}
				// After regenerate, session data is reset — mirror real express-session behaviour.
				const fresh: Record<string, unknown> = {
					regenerate: this.regenerate,
					save: this.save,
					destroy: this.destroy,
				};
				Object.assign(req as unknown as { session: Record<string, unknown> }, { session: fresh });
				cb(null);
			},
			save(cb: (err: null) => void) {
				cb(null);
			},
			destroy(cb: (err: Error | null) => void) {
				if (destroyError) {
					cb(destroyError);
					return;
				}
				cb(null);
			},
		};
		next();
	});

	const router = createRouter(express, {
		userRepository,
		config,
		...(userSessionStore !== undefined ? { userSessionStore } : {}),
		...(sessionTtlMs !== undefined ? { sessionTtlMs } : {}),
	});

	// Pre-router middleware: register a res.on('finish') listener before the route
	// handler runs. When the route sends its response, finish fires and we snapshot
	// req.session (which has already been mutated by the regenerate callback).
	const capturedSession: { current: Record<string, unknown> | null } = { current: null };
	app.use("/session", (req, res, next) => {
		res.on("finish", () => {
			capturedSession.current = (req as unknown as { session: Record<string, unknown> }).session;
		});
		next();
	});

	app.use("/session", router);

	return { app, capturedSession };
}

describe("Session routes — POST /session/login", () => {
	describe("happy path", () => {
		it("returns 200 and sets isAuthenticated when credentials are valid", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged in successfully" });
		});

		it("creates a UserSession record and sets req.session.sid when userSessionStore is wired", async () => {
			const store = makeUserSessionStore();

			const { app, capturedSession } = buildApp({
				userRepository: {
					authenticate: vi.fn().mockResolvedValue({
						id: "u-local-1",
						username: "alice",
						email: "alice@example.com",
						name: "Alice",
					}),
					authenticateByToken: vi.fn(),
				} as unknown as UserRepository,
				userSessionStore: store,
				sessionTtlMs: 3600_000,
			});

			const res = await loginRequest(app)
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged in successfully" });

			// UserSession was created in the store
			expect(store.sessions).toHaveLength(1);
			const saved = store.sessions[0] as {
				sid: string;
				sub: string;
				claims: Record<string, unknown>;
				authTime: unknown;
				expiresAt: unknown;
			};

			// sid is a non-empty UUID-shaped string
			expect(typeof saved.sid).toBe("string");
			expect(saved.sid.length).toBeGreaterThan(0);

			// sub matches user.id
			expect(saved.sub).toBe("u-local-1");

			// claims extracted from user
			expect(saved.claims).toMatchObject({
				email: "alice@example.com",
				name: "Alice",
			});

			// authTime and expiresAt are present
			expect(saved.authTime).toBeTruthy();
			expect(saved.expiresAt).toBeTruthy();

			// req.session.sid must equal the store's sid after regenerate completes
			expect(capturedSession.current).not.toBeNull();
			expect(capturedSession.current?.sid).toBe(saved.sid);
		});

		it("does not crash and does not create a UserSession when userSessionStore is not wired (backward compat)", async () => {
			const { app } = buildApp({
				userRepository: {
					authenticate: vi.fn().mockResolvedValue({ id: "u-no-store", username: "bob" }),
					authenticateByToken: vi.fn(),
				} as unknown as UserRepository,
			});

			const res = await loginRequest(app)
				.send("username=bob&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			// Login still succeeds — backward compat
			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged in successfully" });
		});
	});

	describe("invalid credentials", () => {
		it("returns 401 with RFC 6749 §5.2 error shape when authenticate returns null", async () => {
			const { app } = buildApp({
				userRepository: {
					authenticate: vi.fn().mockResolvedValue(null),
					authenticateByToken: vi.fn(),
				} as unknown as UserRepository,
			});

			const res = await loginRequest(app)
				.send("username=alice&password=wrong")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(401);
			expect(res.body).toMatchObject({
				error: "invalid_credentials",
				error_description: expect.any(String),
			});
		});
	});

	describe("missing credentials", () => {
		it("returns 400 with RFC 6749 error shape when username is missing", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send("password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({
				error: "invalid_request",
				error_description: expect.any(String),
			});
		});

		it("returns 400 with RFC 6749 error shape when password is missing", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send("username=alice")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({
				error: "invalid_request",
				error_description: expect.any(String),
			});
		});
	});

	describe("authentication error", () => {
		it("returns 503 temporarily_unavailable when authenticate throws (user directory outage)", async () => {
			const { app } = buildApp({
				userRepository: {
					authenticate: vi.fn().mockRejectedValue(new Error("db failure")),
					authenticateByToken: vi.fn(),
				} as unknown as UserRepository,
			});

			const res = await loginRequest(app)
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({
				error: "temporarily_unavailable",
			});
		});

		it("returns 503 temporarily_unavailable when userSessionStore.create throws (fail-closed)", async () => {
			const throwingStore: UserSessionStore = {
				kind: "memory",
				async create() {
					throw new Error("redis down");
				},
				async get() {
					return null;
				},
				async delete() {},
			};

			const { app } = buildApp({
				userRepository: {
					authenticate: vi.fn().mockResolvedValue({
						id: "u-503",
						username: "carol",
					}),
					authenticateByToken: vi.fn(),
				} as unknown as UserRepository,
				userSessionStore: throwingStore,
				sessionTtlMs: 3600_000,
			});

			const res = await loginRequest(app)
				.send("username=carol&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({
				error: "temporarily_unavailable",
			});
		});
	});

	describe("redirect_to validation", () => {
		it("rejects non-string redirect_to with 400", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: ["array"] })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_redirect" });
		});

		it("rejects non-http/https redirect_to scheme with 400", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: "ftp://evil.example.com/" })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_redirect" });
		});
	});

	// AS-1 RFC 6749 §5.2 envelope unification — the 3 historically `{message: …}`
	// error responses on this router migrate to `{error, error_description}`.
	describe("AS-1: RFC 6749 §5.2 error envelope", () => {
		it("CSRF origin mismatch returns 403 access_denied with error_description (no `message`)", async () => {
			const { app } = buildApp({
				config: {
					...stubConfig,
					session: {
						...(stubConfig.session as Record<string, unknown>),
						csrf: { trustedOrigins: ["https://app.example.com"], ttlSeconds: 7200 },
					},
				} as unknown as AppConfig,
			});

			const res = await loginRequest(app)
				.set("Origin", "https://evil.example.com")
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(403);
			expect(res.body).toMatchObject({
				error: "access_denied",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});

		it("session regeneration failure returns 500 server_error envelope (no `message`)", async () => {
			const { app } = buildApp({
				userSessionStore: makeUserSessionStore(),
				sessionTtlMs: 3600_000,
				regenerateError: new Error("regenerate failed"),
			});

			const res = await loginRequest(app)
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(500);
			expect(res.body).toMatchObject({
				error: "server_error",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});

		it("logout session destroy failure returns 500 server_error envelope (no `message`)", async () => {
			const { app } = buildApp({
				destroyError: new Error("destroy failed"),
			});

			const res = await logoutRequest(app);

			expect(res.status).toBe(500);
			expect(res.body).toMatchObject({
				error: "server_error",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});
	});

	/**
	 * Issue #272 — the old guard read `Origin` and called `next()` when it was
	 * missing, so omitting the header skipped the check entirely. `sameSite=lax`
	 * covers session-riding, but login CSRF (forcing a victim's browser to
	 * authenticate as the attacker) needs no cookie of the victim's at all.
	 */
	describe("#272: CSRF acceptance rule", () => {
		it("rejects a login carrying neither an origin signal nor a token", async () => {
			const { app } = buildApp();

			const res = await request(app)
				.post("/session/login")
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(403);
			expect(res.body).toMatchObject({ error: "access_denied" });
		});

		it("rejects a logout carrying neither an origin signal nor a token", async () => {
			const { app } = buildApp();

			const res = await request(app).post("/session/logout");

			expect(res.status).toBe(403);
			expect(res.body).toMatchObject({ error: "access_denied" });
		});

		it("accepts a login presenting a valid double-submit token and no Origin", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(200);
		});

		it("accepts the token in the form body when the client cannot set headers", async () => {
			const { app } = buildApp();

			const res = await request(app)
				.post("/session/login")
				.set("Cookie", `${csrf.cookieName}=${csrfToken}`)
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send(`username=alice&password=secret&csrf_token=${encodeURIComponent(csrfToken)}`);

			expect(res.status).toBe(200);
		});

		it("accepts a same-origin browser login that carries no token", async () => {
			const { app } = buildApp();
			const server = app.listen(0);
			try {
				const address = server.address();
				const port = typeof address === "object" && address !== null ? address.port : 0;

				const res = await request(server)
					.post("/session/login")
					.set("Origin", `http://127.0.0.1:${port}`)
					.set("Content-Type", "application/x-www-form-urlencoded")
					.send("username=alice&password=secret");

				expect(res.status).toBe(200);
			} finally {
				server.close();
			}
		});

		it("no longer grants CSRF trust to cors.allowedOrigins", async () => {
			// The CORS list is a resource-sharing policy; reusing it as the CSRF
			// trust list conflated two decisions. Trust is now stated on
			// `session.csrf.trustedOrigins`.
			const { app } = buildApp({
				config: {
					...stubConfig,
					cors: { allowedOrigins: ["https://app.example.com"] },
				} as unknown as AppConfig,
			});

			const res = await request(app)
				.post("/session/login")
				.set("Origin", "https://app.example.com")
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(403);
		});

		it("accepts an origin listed on session.csrf.trustedOrigins", async () => {
			const { app } = buildApp({
				config: {
					...stubConfig,
					session: {
						...(stubConfig.session as Record<string, unknown>),
						csrf: { trustedOrigins: ["https://app.example.com"], ttlSeconds: 7200 },
					},
				} as unknown as AppConfig,
			});

			const res = await request(app)
				.post("/session/login")
				.set("Origin", "https://app.example.com")
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(200);
		});

		it("issues a token pair from GET /session/csrf", async () => {
			const { app } = buildApp();

			const res = await request(app).get("/session/csrf");

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({
				csrf_token: expect.any(String),
				cookie_name: "auth.session.csrf",
				header_name: "x-csrf-token",
			});

			// The pair it hands out has to be one the login route accepts, or the
			// endpoint is decoration.
			const token = res.body.csrf_token as string;
			const login = await request(app)
				.post("/session/login")
				.set("Cookie", `${res.body.cookie_name}=${encodeURIComponent(token)}`)
				.set(res.body.header_name as string, token)
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(login.status).toBe(200);
		});

		it("refreshes the CSRF cookie on a successful login", async () => {
			// After `req.session.regenerate()` the client is on a new session; it
			// gets a fresh token in the same response so the follow-up logout does
			// not need another round trip.
			const { app } = buildApp();

			const res = await loginRequest(app)
				.set("Content-Type", "application/x-www-form-urlencoded")
				.send("username=alice&password=secret");

			expect(res.status).toBe(200);
			const setCookie = (res.headers["set-cookie"] ?? []) as unknown as string[];
			expect(setCookie.some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
		});
	});
});
