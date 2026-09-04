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

import type {
	AppConfig,
	FederationTokenStore,
	Logger,
	SessionFederationIndex,
	SubjectSessionIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
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
 * `stubConfig` with the session slice overridden — the redirect allowlist and
 * the cookie domain are the two keys #405's policy is built from.
 */
const configWith = (session: {
	readonly domain?: string | null;
	readonly redirectAllowlist?: readonly string[];
}): AppConfig =>
	({
		...stubConfig,
		session: { ...stubConfig.session, ...session },
	}) as unknown as AppConfig;

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
 * A `UserSessionStore` backed by a real Map, so a logout's delete is
 * observable rather than merely "was the spy called".
 */
function makeLiveUserSessionStore(
	seed: readonly string[] = [],
): UserSessionStore & { readonly live: Map<string, unknown> } {
	const live = new Map<string, unknown>(
		seed.map((sid) => [
			sid,
			{
				sid,
				sub: "u-1",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: {},
			},
		]),
	);
	return {
		kind: "memory",
		live,
		async create() {},
		async get(sid: string) {
			return live.get(sid) ?? null;
		},
		async delete(sid: string) {
			live.delete(sid);
		},
	} as unknown as UserSessionStore & { readonly live: Map<string, unknown> };
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
		subjectSessionIndex?: SubjectSessionIndex;
		federationTokenStore?: FederationTokenStore;
		sessionFederationIndex?: SessionFederationIndex;
		logger?: Logger;
		/**
		 * Fields the express-session bag already carries when the request
		 * arrives — how a logout sees the session a prior login established.
		 */
		initialSession?: Record<string, unknown>;
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
		subjectSessionIndex,
		federationTokenStore,
		sessionFederationIndex,
		logger,
		initialSession,
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
		const sessionData: Record<string, unknown> = { ...(initialSession ?? {}) };
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
				// Mirror express-session: the bag is gone once destroyed. This
				// is what pins "read `sid` BEFORE destroying" — a handler that
				// reads it afterwards finds `undefined` and invalidates nothing.
				const bag = (req as unknown as { session: Record<string, unknown> }).session;
				for (const key of ["sid", "user", "isAuthenticated", "redirectTo"]) {
					delete bag[key];
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
		...(subjectSessionIndex !== undefined ? { subjectSessionIndex } : {}),
		...(federationTokenStore !== undefined ? { federationTokenStore } : {}),
		...(sessionFederationIndex !== undefined ? { sessionFederationIndex } : {}),
		...(logger !== undefined ? { logger } : {}),
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

	/**
	 * #405 — `redirect_to` is held to the same exact-match allowlist #278 gave
	 * the federation flow, and an absent allowlist is the empty allowlist.
	 *
	 * The pre-#405 rule here was "any absolute http(s) URL, narrowed to
	 * `session.domain` if one is configured". `session.domain` is nullable and
	 * defaults to null, so the shipped default stored any URL on the internet
	 * under `req.session.redirectTo` — the exact shape #278 removed one route
	 * over. Nothing in this repository redirects to that key today, but it is
	 * declared public on `SessionData` and `MfaResumeState`'s `flow: "login"`
	 * variant designs a consumer for it, so a validated value is what an
	 * embedder must be handed.
	 */
	describe("redirect_to validation (#405)", () => {
		const reasonOf = (description: unknown): string | undefined =>
			typeof description === "string" ? /\(reason: ([a-z-]+)\)/.exec(description)?.[1] : undefined;

		it("rejects non-string redirect_to with 400", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: ["array"] })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_redirect" });
			expect(reasonOf(res.body.error_description)).toBe("not-a-string");
		});

		it("rejects non-http/https redirect_to scheme with 400", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: "ftp://evil.example.com/" })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_redirect" });
			expect(reasonOf(res.body.error_description)).toBe("unsupported-scheme");
		});

		// The #405 finding itself: this is the request that used to succeed.
		it("refuses any absolute https URL when no allowlist is configured", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: "https://evil.example/" })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_redirect" });
			expect(reasonOf(res.body.error_description)).toBe("no-allowlist");
		});

		it("names the session config key an operator has to set, not the federation one", async () => {
			const { app } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret", redirect_to: "https://evil.example/" })
				.set("Content-Type", "application/json");

			expect(res.body.error_description).toContain("session.redirectAllowlist");
			expect(res.body.error_description).not.toContain("federation");
		});

		it("accepts an exact allowlist match and stores it on the session", async () => {
			const { app, capturedSession } = buildApp({
				config: configWith({ redirectAllowlist: ["https://app.example.com/welcome"] }),
			});

			const res = await loginRequest(app)
				.send({
					username: "alice",
					password: "secret",
					redirect_to: "https://app.example.com/welcome",
				})
				.set("Content-Type", "application/json");

			expect(res.status).toBe(200);
			expect(capturedSession.current?.redirectTo).toBe("https://app.example.com/welcome");
		});

		it("refuses a URL the allowlist does not name exactly", async () => {
			const { app, capturedSession } = buildApp({
				config: configWith({ redirectAllowlist: ["https://app.example.com/welcome"] }),
			});

			const res = await loginRequest(app)
				.send({
					username: "alice",
					password: "secret",
					redirect_to: "https://app.example.com/welcome?next=//evil.example",
				})
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(reasonOf(res.body.error_description)).toBe("not-allowlisted");
			expect(capturedSession.current?.redirectTo).toBeUndefined();
		});

		// `https://app.example.com@evil.example/` parses with host `evil.example`.
		it("refuses a URL that embeds credentials", async () => {
			const { app } = buildApp({
				config: configWith({ redirectAllowlist: ["https://app.example.com/welcome"] }),
			});

			const res = await loginRequest(app)
				.send({
					username: "alice",
					password: "secret",
					redirect_to: "https://app.example.com@evil.example/welcome",
				})
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(reasonOf(res.body.error_description)).toBe("has-credentials");
		});

		it("refuses http on a non-loopback host before it ever reaches the allowlist", async () => {
			const { app } = buildApp({
				config: configWith({ redirectAllowlist: ["https://app.example.com/welcome"] }),
			});

			const res = await loginRequest(app)
				.send({
					username: "alice",
					password: "secret",
					redirect_to: "http://app.example.com/welcome",
				})
				.set("Content-Type", "application/json");

			expect(res.status).toBe(400);
			expect(reasonOf(res.body.error_description)).toBe("insecure-scheme");
		});

		// RFC 8252 §7.3 — a native client's loopback listener has no certificate.
		it("accepts an allowlisted http loopback target", async () => {
			const { app, capturedSession } = buildApp({
				config: configWith({ redirectAllowlist: ["http://127.0.0.1:3000/callback"] }),
			});

			const res = await loginRequest(app)
				.send({
					username: "alice",
					password: "secret",
					redirect_to: "http://127.0.0.1:3000/callback",
				})
				.set("Content-Type", "application/json");

			expect(res.status).toBe(200);
			expect(capturedSession.current?.redirectTo).toBe("http://127.0.0.1:3000/callback");
		});

		// A deployment that never sends `redirect_to` is unaffected.
		it("leaves a login without redirect_to alone", async () => {
			const { app, capturedSession } = buildApp();

			const res = await loginRequest(app)
				.send({ username: "alice", password: "secret" })
				.set("Content-Type", "application/json");

			expect(res.status).toBe(200);
			expect(capturedSession.current?.redirectTo).toBeUndefined();
		});

		// Same as the federation policy: a dead allowlist entry is a boot failure,
		// not a redirect that is silently refused at request time.
		it("refuses at construction an allowlist entry outside session.domain", () => {
			expect(() =>
				buildApp({
					config: configWith({
						domain: ".example.com",
						redirectAllowlist: ["https://app.other.example/welcome"],
					}),
				}),
			).toThrow(/redirectAllowlist\[0\].*outside-session-domain/s);
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

// ---------------------------------------------------------------------------
// #296 — subject-keyed session index on local login
//
// `revokeAllForSubject` enumerates this index after a credential change, so a
// session that never lands in it is a session a password reset cannot kill.
// That is why the write happens as soon as the session exists and why the
// regeneration rollback removes it again.
// ---------------------------------------------------------------------------

function makeSubjectSessionIndex(override?: Partial<SubjectSessionIndex>): SubjectSessionIndex & {
	addSid: ReturnType<typeof vi.fn>;
	removeSid: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		addSid: vi.fn(async () => {}),
		listSids: vi.fn(async () => []),
		removeSid: vi.fn(async () => {}),
		removeBySubject: vi.fn(async () => {}),
		...override,
	} as SubjectSessionIndex & {
		addSid: ReturnType<typeof vi.fn>;
		removeSid: ReturnType<typeof vi.fn>;
	};
}

describe("Session routes — subject session index (#296)", () => {
	it("records the sid against the subject on a successful login", async () => {
		const index = makeSubjectSessionIndex();
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(200);
		expect(index.addSid).toHaveBeenCalledOnce();
		const [sub, sid, expiresAt] = index.addSid.mock.calls[0] as [string, string, Date];
		expect(sub).toBe("u-1");
		expect(typeof sid).toBe("string");
		// The TTL contract: the entry ages out with the session it names, so an
		// abandoned session cannot accumulate against a long-lived user.
		expect(expiresAt).toBeInstanceOf(Date);
	});

	it("does not deny a legitimate login when the index write fails", async () => {
		// An index outage must not become an authentication outage. The cost is
		// one session this deployment cannot subject-revoke, so it is logged.
		const index = makeSubjectSessionIndex({
			addSid: vi.fn(async () => {
				throw new Error("index store down");
			}),
		});
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(200);
	});

	it("removes the entry when session regeneration fails and the session is rolled back", async () => {
		const index = makeSubjectSessionIndex();
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
			regenerateError: new Error("regenerate failed"),
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(500);
		expect(index.addSid).toHaveBeenCalledOnce();
		expect(index.removeSid).toHaveBeenCalledOnce();
		const [, removedSid] = index.removeSid.mock.calls[0] as [string, string];
		expect(removedSid).toBe(index.addSid.mock.calls[0][1]);
	});

	it("survives a rollback whose removeSid itself throws", async () => {
		const index = makeSubjectSessionIndex({
			removeSid: vi.fn(async () => {
				throw new Error("index store down");
			}),
		});
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
			regenerateError: new Error("regenerate failed"),
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(500);
	});

	it("logs in normally when no index is wired", async () => {
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			sessionTtlMs: 3600_000,
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(200);
	});
});

/**
 * `/session/logout` must invalidate the `UserSession` record, not only the
 * cookie.
 *
 * #506 stamped `sid` on the `session` grant's access token and gave
 * `/oauth/introspect` the liveness check `/oauth/userinfo` already ran. Both
 * resolve the `UserSession` record — which this endpoint used to leave alive.
 * So in the BFF / `auth.proxy` injection topology, whose logout is exactly
 * this endpoint, a token minted from the session kept introspecting
 * `active: true` and kept answering at `/userinfo` for its full lifetime
 * after the user logged out. `/oauth/logout` was unaffected; it runs the full
 * cascade. This suite pins the endpoint's own half.
 */
describe("Session routes — POST /session/logout invalidates the session record", () => {
	/** A logged-in bag: what a prior `POST /session/login` leaves behind. */
	const loggedIn = (sid = "sid-1") => ({
		isAuthenticated: true,
		sid,
		user: { id: "u-1", username: "alice" },
	});

	const silentLogger = () =>
		({
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		}) as unknown as Logger & { error: ReturnType<typeof vi.fn> };

	it("deletes the UserSession record named by req.session.sid", async () => {
		const store = makeLiveUserSessionStore(["sid-1"]);
		const { app } = buildApp({ userSessionStore: store, initialSession: loggedIn() });

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ message: "Logged out successfully" });
		// The record the liveness checks in `/oauth/introspect` and
		// `/oauth/userinfo` resolve is gone, so a token carrying this `sid`
		// stops being honoured.
		expect(store.live.has("sid-1")).toBe(false);
	});

	it("removes the subject-index entry, as the login rollback path already does", async () => {
		const removeSid = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({
			userSessionStore: makeLiveUserSessionStore(["sid-1"]),
			subjectSessionIndex: {
				kind: "memory",
				addSid: vi.fn(),
				listSids: vi.fn(),
				removeSid,
				removeBySubject: vi.fn(),
			} as unknown as SubjectSessionIndex,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		// #296: leaving the entry would have `revokeAllForSubject` enumerate a
		// sid that no longer exists.
		expect(removeSid).toHaveBeenCalledWith("u-1", "sid-1");
	});

	it("removes the federation token store and federation index entries for the sid", async () => {
		const removeFederationTokens = vi.fn().mockResolvedValue(undefined);
		const removeFederationIndex = vi.fn().mockResolvedValue(undefined);
		const { app } = buildApp({
			userSessionStore: makeLiveUserSessionStore(["sid-1"]),
			federationTokenStore: {
				kind: "memory",
				attach: vi.fn(),
				get: vi.fn(),
				update: vi.fn(),
				removeBySid: removeFederationTokens,
			} as unknown as FederationTokenStore,
			sessionFederationIndex: {
				kind: "memory",
				addFederation: vi.fn(),
				listFederations: vi.fn(),
				removeFederation: vi.fn(),
				removeBySid: removeFederationIndex,
			} as unknown as SessionFederationIndex,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(removeFederationTokens).toHaveBeenCalledWith("sid-1");
		expect(removeFederationIndex).toHaveBeenCalledWith("sid-1");
	});

	it("logs out cleanly in a composition wiring no userSessionStore", async () => {
		// The backward-compatible shape: no stores at all, nothing to
		// invalidate, and the endpoint still has to end the browser session.
		const { app } = buildApp({ initialSession: loggedIn() });

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ message: "Logged out successfully" });
	});

	it("takes no store action when the session carries no sid", async () => {
		const store = makeLiveUserSessionStore(["sid-1"]);
		const deleteSpy = vi.spyOn(store, "delete");
		const { app } = buildApp({
			userSessionStore: store,
			// A deployment whose own login route sets `isAuthenticated` without
			// recording a `sid` — a supported wiring. There is no record to name.
			initialSession: { isAuthenticated: true, user: { id: "u-1" } },
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(deleteSpy).not.toHaveBeenCalled();
		expect(store.live.has("sid-1")).toBe(true);
	});

	it("still logs the browser out, and logs the failure, when the store delete throws", async () => {
		const logger = silentLogger();
		const { app } = buildApp({
			userSessionStore: {
				kind: "memory",
				create: vi.fn(),
				get: vi.fn(),
				delete: vi.fn().mockRejectedValue(new Error("store down")),
			} as unknown as UserSessionStore,
			logger,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		// A store outage must not turn a logout into a 5xx that leaves the user
		// holding a live cookie: the cookie is the half this endpoint can always
		// deliver, and `/authorize`'s R1b liveness check covers the residue.
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ message: "Logged out successfully" });
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-1" }),
			"logout_user_session_delete_failed",
		);
	});

	it("does not let a federation-store outage stop the primary invalidation", async () => {
		const logger = silentLogger();
		const store = makeLiveUserSessionStore(["sid-1"]);
		const { app } = buildApp({
			userSessionStore: store,
			federationTokenStore: {
				kind: "memory",
				attach: vi.fn(),
				get: vi.fn(),
				update: vi.fn(),
				removeBySid: vi.fn().mockRejectedValue(new Error("federation store down")),
			} as unknown as FederationTokenStore,
			logger,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		// Primary invalidation runs FIRST and is not conditional on the
		// best-effort hygiene that follows it.
		expect(store.live.has("sid-1")).toBe(false);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-1" }),
			"logout_federation_token_remove_failed",
		);
	});

	// The two index removals are the remaining best-effort steps, and their
	// failure paths were the only lines of `invalidateSessionRecords` no test
	// reached. Both are hygiene rather than containment — the `UserSession` is
	// already gone by the time they run — so the contract they have to keep is
	// that the failure is visible and costs the caller nothing.
	it("does not let a subject-index outage stop the primary invalidation", async () => {
		const logger = silentLogger();
		const store = makeLiveUserSessionStore(["sid-1"]);
		const { app } = buildApp({
			userSessionStore: store,
			subjectSessionIndex: {
				addSid: vi.fn(),
				removeSid: vi.fn().mockRejectedValue(new Error("subject index down")),
				pruneExpiredAndList: vi.fn(),
			} as unknown as SubjectSessionIndex,
			logger,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(store.live.has("sid-1")).toBe(false);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-1", sub: "u-1" }),
			"logout_subject_session_index_remove_failed",
		);
	});

	it("does not let a federation-index outage stop the primary invalidation", async () => {
		const logger = silentLogger();
		const store = makeLiveUserSessionStore(["sid-1"]);
		const { app } = buildApp({
			userSessionStore: store,
			sessionFederationIndex: {
				addFederation: vi.fn(),
				removeFederation: vi.fn(),
				listFederations: vi.fn(),
				removeBySid: vi.fn().mockRejectedValue(new Error("federation index down")),
			} as unknown as SessionFederationIndex,
			logger,
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(store.live.has("sid-1")).toBe(false);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-1" }),
			"logout_session_federation_index_remove_failed",
		);
	});

	it("keeps the 500 envelope when the cookie destroy itself fails", async () => {
		// Pre-existing contract, deliberately unchanged: if the browser session
		// survives, the logout did not happen from the browser's point of view.
		const store = makeLiveUserSessionStore(["sid-1"]);
		const { app } = buildApp({
			userSessionStore: store,
			destroyError: new Error("destroy failed"),
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(500);
		expect(res.body).toMatchObject({ error: "server_error" });
		// The record still went, so the token minted from this session is dead
		// even though the cookie survived.
		expect(store.live.has("sid-1")).toBe(false);
	});
});
