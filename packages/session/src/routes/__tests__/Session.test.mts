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
	admitSession,
	cookieClaim,
	createInMemoryUserSessionStore,
	type DeploymentMode,
	type Logger,
	newRenewalNonce,
	type SessionLifecycle,
	type SubjectSessionIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestCsrfTokenSigner, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { fakeSessionLifecycle } from "#/__tests__/_helpers/sessionLifecycle.mjs";
import { createCsrfProtection } from "#/csrf.mjs";
import { createRouter } from "#/routes/Session.mjs";

/**
 * Minimal configuration stub: the session module's section, `session`, and
 * the session cookie the store's section, `session-store`, describes, which
 * the router receives through the `sessionCookiePolicy` slot.
 */
const stubConfig = {
	cors: { allowedOrigins: [] },
	session: {
		rateLimit: {
			login: { windowMs: 60_000, limit: 100 },
		},
	},
	"session-store": {
		name: "auth.session",
		secure: false,
		sameSite: "lax",
		domain: null,
	},
} as unknown as AppConfig;

/**
 * `stubConfig` with the redirect allowlist and the cookie domain overridden —
 * the two keys the `redirect_to` policy is built from.
 */
const configWith = (settings: {
	readonly domain?: string | null;
	readonly redirectAllowlist?: readonly string[];
}): AppConfig => {
	const { domain, redirectAllowlist } = settings;
	const stub = stubConfig as unknown as Record<string, Record<string, unknown>>;
	return {
		...stub,
		session: {
			...stub.session,
			...(redirectAllowlist === undefined ? {} : { redirectAllowlist }),
		},
		"session-store": { ...stub["session-store"], ...(domain === undefined ? {} : { domain }) },
	} as unknown as AppConfig;
};

/** The session cookie a configuration's `session-store` describes, as the `sessionCookiePolicy` slot carries it. */
const cookieOf = (config: AppConfig) => {
	const cookie = (config as unknown as { "session-store": Record<string, unknown> })[
		"session-store"
	] as {
		name: string;
		secure: boolean;
		sameSite: "lax" | "strict" | "none";
		domain: string | null;
	};
	return {
		name: cookie.name,
		secure: cookie.secure,
		sameSite: cookie.sameSite,
		domain: cookie.domain ?? undefined,
	};
};

/**
 * A double-submit pair minted with the signer the router is given and the
 * cookie name it derives from `stubConfig`. The state-changing session routes
 * reject a request carrying neither an origin signal nor a token, and
 * `supertest` sends no `Origin` — which is exactly the header-less API client
 * the token arm exists to keep working.
 */
const SIGNER = createTestCsrfTokenSigner();
const csrf = createCsrfProtection({
	signer: SIGNER,
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
				amr: undefined,
				authentication: undefined,
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
 * `userRepository.authenticate` resolving to a User logs in, resolving to
 * null is 401 and rejecting is a user directory outage (503).
 * `capturedSession` holds `req.session` as the response left it.
 */
function buildApp(
	opts: {
		userRepository?: UserRepository;
		userSessionStore?: UserSessionStore;
		subjectSessionIndex?: SubjectSessionIndex;
		/** With a `userSessionStore` and none given, a fresh fake. */
		sessionLifecycle?: SessionLifecycle;
		logger?: Logger;
		/**
		 * Fields the express-session bag already carries when the request
		 * arrives — how a logout sees the session a prior login established.
		 */
		initialSession?: Record<string, unknown>;
		sessionTtlMs?: number;
		regenerateError?: Error;
		destroyError?: Error;
		saveError?: Error;
		config?: AppConfig;
		/** The `deploymentMode` slot's value; `unset` warns about the per-process login limiter. */
		deploymentMode?: DeploymentMode;
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
		sessionLifecycle = userSessionStore === undefined ? undefined : fakeSessionLifecycle(),
		logger,
		initialSession,
		sessionTtlMs,
		regenerateError,
		destroyError,
		saveError,
		config = stubConfig,
		deploymentMode = "unset",
	} = opts;

	const app = express();

	// Minimal express-session stub so req.session.regenerate / destroy / save work.
	// regenerateError/destroyError opt-ins simulate cookie-store failures, which
	// the routes answer as the outage they are (503 temporarily_unavailable).
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
			save(cb: (err: Error | null) => void) {
				cb(saveError ?? null);
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
				for (const key of ["sid", "user", "isAuthenticated", "redirectTo", "renewalNonce"]) {
					delete bag[key];
				}
				cb(null);
			},
		};
		next();
	});

	const router = createRouter(express, {
		csrfTokenSigner: SIGNER,
		userRepository,
		section: (config as unknown as { session: Record<string, unknown> }).session,
		sessionCookie: cookieOf(config),
		deploymentMode,
		requirements: resolverForTests([]),
		...(userSessionStore !== undefined ? { userSessionStore } : {}),
		...(subjectSessionIndex !== undefined ? { subjectSessionIndex } : {}),
		...(sessionLifecycle !== undefined ? { sessionLifecycle } : {}),
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
				sessionLifecycle: fakeSessionLifecycle(),
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
			// A password login records how the user authenticated (RFC 8176).
			expect((saved as { amr?: unknown }).amr).toEqual(["pwd"]);
			// And that its primary was a password, with no second factor verified
			// — every field named (ADR 2026-09-25-multi-factor-authentication, D9).
			expect(saved).toHaveProperty("authentication");
			expect((saved as { authentication?: unknown }).authentication).toStrictEqual({
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			});

			// req.session.sid must equal the store's sid after regenerate completes
			expect(capturedSession.current).not.toBeNull();
			expect(capturedSession.current?.sid).toBe(saved.sid);
		});

		it("logs in when userSessionStore is not wired", async () => {
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
				sessionLifecycle: fakeSessionLifecycle(),
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
	 * `redirect_to` is held to the federation flow's exact-match allowlist, and
	 * an absent allowlist is the empty allowlist. `session-store.domain`
	 * defaults to null, so "any absolute http(s) URL, narrowed to the domain" would
	 * store any URL on the internet by default. `req.session.redirectTo` is
	 * public on `SessionData`, and an MFA login transaction carries it back to
	 * the page (`MfaTransaction.redirectTo`), so an embedder must be handed a
	 * validated value.
	 */
	describe("redirect_to validation", () => {
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
		it("refuses at construction an allowlist entry outside session-store.domain", () => {
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

	// The RFC 6749 §5.2 envelope, `{error, error_description}`, with no `message`.
	describe("RFC 6749 §5.2 error envelope", () => {
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

		it("session regeneration failure returns the 503 temporarily_unavailable envelope (no `message`)", async () => {
			const { app } = buildApp({
				userSessionStore: makeUserSessionStore(),
				sessionLifecycle: fakeSessionLifecycle(),
				sessionTtlMs: 3600_000,
				regenerateError: new Error("regenerate failed"),
			});

			const res = await loginRequest(app)
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({
				error: "temporarily_unavailable",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});

		it("logout session destroy failure returns the 503 temporarily_unavailable envelope (no `message`)", async () => {
			const { app } = buildApp({
				destroyError: new Error("destroy failed"),
			});

			const res = await logoutRequest(app);

			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({
				error: "temporarily_unavailable",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});
	});

	/**
	 * A missing `Origin` must not skip the check. `sameSite=lax` covers
	 * session-riding, but login CSRF (forcing a victim's browser to
	 * authenticate as the attacker) needs no cookie of the victim's at all.
	 */
	describe("CSRF acceptance rule", () => {
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
			// Bound to the loopback address the request dials — a hostless
			// listen can share its port with another process's 127.0.0.1 socket.
			const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
				const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
			});
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

		it("does not grant CSRF trust to cors.allowedOrigins", async () => {
			// The CORS list is a resource-sharing policy, not the CSRF trust list:
			// trust is stated on `session.csrf.trustedOrigins`.
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
// Subject-keyed session index on local login
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

describe("Session routes — the session lifecycle, where it is installed", () => {
	const lifecycleAnswering = (outcome: "opened" | Error) => {
		const open = vi.fn(async () => {
			if (outcome instanceof Error) throw outcome;
			return { outcome };
		});
		return { open, lifecycle: { open } as unknown as SessionLifecycle };
	};

	it("a login opens the session's lifecycle record for the record's sid, subject and end", async () => {
		const store = makeUserSessionStore();
		const { open, lifecycle } = lifecycleAnswering("opened");
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle: lifecycle,
			sessionTtlMs: 3600_000,
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(200);
		const created = store.sessions[0] as { sid: string; sub: string; expiresAt: Date };
		expect(open).toHaveBeenCalledExactlyOnceWith(created.sid, {
			sub: "u-1",
			expiresAt: created.expiresAt,
		});
	});

	it("a login whose lifecycle record cannot be opened is a 503, with no session record", async () => {
		const store = makeUserSessionStore();
		const { lifecycle } = lifecycleAnswering(new Error("lifecycle store down"));
		const { app, capturedSession } = buildApp({
			userSessionStore: store,
			sessionLifecycle: lifecycle,
			sessionTtlMs: 3600_000,
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(503);
		expect(store.sessions).toEqual([]);
		expect(capturedSession.current).not.toHaveProperty("isAuthenticated");
	});
});

describe("Session routes — subject session index", () => {
	it("records the sid against the subject on a successful login", async () => {
		const index = makeSubjectSessionIndex();
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			sessionLifecycle: fakeSessionLifecycle(),
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
			sessionLifecycle: fakeSessionLifecycle(),
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
			sessionLifecycle: fakeSessionLifecycle(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
			regenerateError: new Error("regenerate failed"),
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(503);
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
			sessionLifecycle: fakeSessionLifecycle(),
			subjectSessionIndex: index,
			sessionTtlMs: 3600_000,
			regenerateError: new Error("regenerate failed"),
		});

		const res = await loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

		expect(res.status).toBe(503);
	});

	it("logs in normally when no index is wired", async () => {
		const { app } = buildApp({
			userSessionStore: makeUserSessionStore(),
			sessionLifecycle: fakeSessionLifecycle(),
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
 * cookie: the `session` grant's access token carries `sid`, and
 * `/oauth/introspect` and `/oauth/userinfo` check that record's liveness. In
 * the BFF / `auth.proxy` injection topology, whose logout is this endpoint, a
 * token minted from the session would otherwise stay live for its full
 * lifetime. See README, What `POST /session/logout` invalidates.
 */
describe("Session routes — POST /session/logout closes the session through the session lifecycle", () => {
	/** A logged-in bag: what a prior `POST /session/login` leaves behind. */
	const loggedIn = (sid = "sid-1") => ({
		isAuthenticated: true,
		sid,
		user: { id: "u-1", username: "alice" },
	});

	it("closes the session named by req.session.sid, and deletes nothing itself", async () => {
		const store = makeLiveUserSessionStore(["sid-1"]);
		const deleteSpy = vi.spyOn(store, "delete");
		const removeSid = vi.fn().mockResolvedValue(undefined);
		const sessionLifecycle = fakeSessionLifecycle();
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle,
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
		expect(res.body).toMatchObject({ message: "Logged out successfully" });
		expect(sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith("sid-1", "session_logout");
		expect(deleteSpy).not.toHaveBeenCalled();
		expect(removeSid).not.toHaveBeenCalled();
	});

	it("logs out cleanly in a composition wiring no userSessionStore", async () => {
		// The sessionless shape: no stores at all, nothing to close, and the
		// endpoint still has to end the browser session.
		const { app } = buildApp({ initialSession: loggedIn() });

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ message: "Logged out successfully" });
	});

	it("closes nothing when the session carries no sid", async () => {
		const sessionLifecycle = fakeSessionLifecycle();
		const { app } = buildApp({
			userSessionStore: makeLiveUserSessionStore(["sid-1"]),
			sessionLifecycle,
			// A deployment whose own login route sets `isAuthenticated` without
			// recording a `sid` — a supported wiring. There is no record to name.
			initialSession: { isAuthenticated: true, user: { id: "u-1" } },
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(200);
		expect(sessionLifecycle.close).not.toHaveBeenCalled();
	});

	it("answers 503 when the cookie destroy itself fails, the session already closed", async () => {
		// If the browser session survives, the logout did not happen from the
		// browser's point of view — and the cookie store that could not destroy
		// it is an outage, so the answer tells the client to retry.
		const sessionLifecycle = fakeSessionLifecycle();
		const { app } = buildApp({
			userSessionStore: makeLiveUserSessionStore(["sid-1"]),
			sessionLifecycle,
			destroyError: new Error("destroy failed"),
			initialSession: loggedIn(),
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith("sid-1", "session_logout");
	});
});

describe("Session routes — POST /session/logout from a cookie session the record was renewed away from", () => {
	/** A record escalated with `nonce`, as a step-up's finish records it after renewing the cookie session. */
	async function escalated(nonce: string) {
		const store = createInMemoryUserSessionStore();
		await store.create({
			sid: "sid-1",
			sub: "u-1",
			authTime: new Date(Date.now() - 60_000),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
		await store.recordSecondFactor("sid-1", {
			amr: ["otp", "mfa"],
			at: new Date(),
			renewalNonce: nonce,
		});
		return store;
	}
	const signedIn = (renewalNonce?: string) => ({
		isAuthenticated: true,
		sid: "sid-1",
		user: { id: "u-1", username: "alice" },
		...(renewalNonce === undefined ? {} : { renewalNonce }),
	});
	/** How admission reads the renewed browser's cookie session over `store`. */
	const admitVictim = (store: UserSessionStore, nonce: string) =>
		admitSession(
			{
				userSessionStore: store,
				subjectRevocation: undefined,
				requirements: resolverForTests([], { actions: { "test.use": { grade: "use" } } }),
				acrTable: {},
				logger: undefined,
				auditSink: undefined,
			},
			{ claim: cookieClaim({ session: signedIn(nonce) }), action: "test.use" },
		);

	it("a stale copy — no nonce, or another — destroys only its own cookie session: the renewed session stays live", async () => {
		const nonce = newRenewalNonce();
		for (const stale of [undefined, newRenewalNonce()]) {
			const store = await escalated(nonce);
			const { app, capturedSession } = buildApp({
				userSessionStore: store,
				sessionLifecycle: fakeSessionLifecycle(),
				initialSession: signedIn(stale),
			});
			const res = await logoutRequest(app);
			expect(res.status, String(stale)).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged out successfully" });
			expect(await store.get("sid-1"), String(stale)).toMatchObject({ renewalNonce: nonce });
			expect(await admitVictim(store, nonce), String(stale)).toMatchObject({ outcome: "admitted" });
			expect(capturedSession.current, String(stale)).not.toHaveProperty("isAuthenticated");
			expect(capturedSession.current, String(stale)).not.toHaveProperty("sid");
		}
	});

	it("the renewed session itself logs out as any session does: the session is closed", async () => {
		const nonce = newRenewalNonce();
		const store = await escalated(nonce);
		const sessionLifecycle = fakeSessionLifecycle();
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle,
			initialSession: signedIn(nonce),
		});
		expect((await logoutRequest(app)).status).toBe(200);
		expect(sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith("sid-1", "session_logout");
	});

	it("a record that cannot be read is logged, and the logout closes the session as before", async () => {
		const live = makeLiveUserSessionStore(["sid-1"]);
		const store = {
			...live,
			get: async () => {
				throw new Error("store down");
			},
		} as unknown as UserSessionStore;
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		} as unknown as Logger & { error: ReturnType<typeof vi.fn> };
		const sessionLifecycle = fakeSessionLifecycle();
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle,
			initialSession: signedIn(),
			logger,
		});
		expect((await logoutRequest(app)).status).toBe(200);
		expect(sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith("sid-1", "session_logout");
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-1" }),
			"logout_user_session_read_failed",
		);
	});
});

// ---------------------------------------------------------------------------
// The outage policy on the session routes: a store the route cannot do
// without is `503 temporarily_unavailable`, logged once at error level —
// `login_store_unavailable` / `session_logout_store_unavailable`, with `store`,
// `step` and the error's projection — and each best-effort rollback step that
// fails is one `login_cleanup_failed` warn.
// ---------------------------------------------------------------------------

describe("Session routes — a store that cannot answer is an outage, logged once", () => {
	const spyLogger = () => {
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		logger.child.mockReturnValue(logger);
		return logger;
	};
	type SpyLogger = ReturnType<typeof spyLogger>;

	/**
	 * Exactly one error line named `event` with `fields` and the error's
	 * projection (never the `Error`); one `login_cleanup_failed` warn per entry
	 * of `cleanups`, in order; nothing at any other level.
	 */
	const expectOutageLogged = (
		logger: SpyLogger,
		event: string,
		fields: Record<string, unknown>,
		detail: string,
		cleanups: ReadonlyArray<Record<string, unknown>> = [],
	): void => {
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe(event);
		expect(context).toMatchObject(fields);
		expect(context.err).not.toBeInstanceOf(Error);
		expect(context.err).toMatchObject({ name: "Error", detail });
		expect(logger.warn).toHaveBeenCalledTimes(cleanups.length);
		cleanups.forEach((cleanup, index) => {
			const [warned, warnName] = logger.warn.mock.calls[index] as [Record<string, unknown>, string];
			expect(warnName).toBe("login_cleanup_failed");
			expect(warned).toMatchObject(cleanup);
			expect(warned.err).not.toBeInstanceOf(Error);
		});
		for (const level of ["trace", "debug", "info", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	};

	// One replica, so the router's construction-time notice about its
	// per-process login limiter is not among the lines a test counts.
	const deploymentMode = "single";

	const login = (app: express.Express) =>
		loginRequest(app)
			.send("username=alice&password=secret")
			.set("Content-Type", "application/x-www-form-urlencoded");

	it("the user directory: 503 and one error line, no username on it", async () => {
		const logger = spyLogger();
		const { app } = buildApp({
			userRepository: {
				authenticate: vi.fn().mockRejectedValue(new Error("directory down")),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "User directory temporarily unavailable",
		});
		expectOutageLogged(
			logger,
			"login_store_unavailable",
			{ store: "user_repository", step: "authenticate" },
			"directory down",
		);
		expect(JSON.stringify(logger.error.mock.calls)).not.toContain("alice");
	});

	it("the session record: 503 and one error line", async () => {
		const logger = spyLogger();
		const { app } = buildApp({
			userSessionStore: {
				kind: "memory",
				create: vi.fn().mockRejectedValue(new Error("session store down")),
				get: vi.fn(),
				delete: vi.fn(),
			} as unknown as UserSessionStore,
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "Session store unavailable",
		});
		expectOutageLogged(
			logger,
			"login_store_unavailable",
			{ store: "user_session", step: "create", sub: "u-1", sid: expect.any(String) },
			"session store down",
		);
	});

	it("the cookie session's regeneration: 503, one error line, and the record rolled back", async () => {
		const logger = spyLogger();
		const store = makeLiveUserSessionStore();
		const created: string[] = [];
		store.create = async (input) => {
			created.push(input.sid);
			store.live.set(input.sid, input);
		};
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle: fakeSessionLifecycle(),
			regenerateError: new Error("cookie store down"),
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "Session store unavailable",
		});
		expectOutageLogged(
			logger,
			"login_store_unavailable",
			{ store: "cookie_session", step: "regenerate", sid: created[0] },
			"cookie store down",
		);
		expect(store.live.size).toBe(0);
	});

	it("the rollback after a failed regeneration: one warn per step that fails", async () => {
		const logger = spyLogger();
		const { app } = buildApp({
			userSessionStore: {
				kind: "memory",
				create: vi.fn(async () => {}),
				get: vi.fn(),
				delete: vi.fn().mockRejectedValue(new Error("session store down")),
			} as unknown as UserSessionStore,
			subjectSessionIndex: makeSubjectSessionIndex({
				removeSid: vi.fn().mockRejectedValue(new Error("subject index down")),
			}),
			regenerateError: new Error("cookie store down"),
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expectOutageLogged(
			logger,
			"login_store_unavailable",
			{ store: "cookie_session", step: "regenerate" },
			"cookie store down",
			[
				{ store: "user_session", step: "delete", sid: expect.any(String) },
				{ store: "subject_session_index", step: "remove_sid", sub: "u-1" },
			],
		);
	});

	it("the regenerated session's save: 503, one error line, and the record rolled back", async () => {
		const logger = spyLogger();
		const store = makeLiveUserSessionStore();
		const created: string[] = [];
		store.create = async (input) => {
			created.push(input.sid);
			store.live.set(input.sid, input);
		};
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle: fakeSessionLifecycle(),
			saveError: new Error("cookie store down"),
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "Session store unavailable",
		});
		expectOutageLogged(
			logger,
			"login_store_unavailable",
			{ store: "cookie_session", step: "save", sid: created[0] },
			"cookie store down",
		);
		expect(store.live.size).toBe(0);
	});

	it("the cookie session's destroy at logout: 503 and one error line", async () => {
		const logger = spyLogger();
		const { app } = buildApp({
			userSessionStore: makeLiveUserSessionStore(["sid-1"]),
			sessionLifecycle: fakeSessionLifecycle(),
			destroyError: new Error("cookie store down"),
			initialSession: { isAuthenticated: true, sid: "sid-1", user: { id: "u-1" } },
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await logoutRequest(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "Session store unavailable",
		});
		expectOutageLogged(
			logger,
			"session_logout_store_unavailable",
			{ store: "cookie_session", step: "destroy", sid: "sid-1" },
			"cookie store down",
		);
	});

	it("the subject index's write: the login succeeds, and the one error line names the sid the record was created with", async () => {
		const logger = spyLogger();
		const store = makeUserSessionStore();
		const { app } = buildApp({
			userSessionStore: store,
			sessionLifecycle: fakeSessionLifecycle(),
			subjectSessionIndex: makeSubjectSessionIndex({
				addSid: vi.fn().mockRejectedValue(new Error("subject index down")),
			}),
			logger: logger as unknown as Logger,
			deploymentMode,
		});

		const res = await login(app);

		expect(res.status).toBe(200);
		const created = store.sessions[0] as { sid: string };
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe("subject_session_index_write_failed");
		expect(context).toMatchObject({ sub: "u-1", sid: created.sid });
		expect(context.err).not.toBeInstanceOf(Error);
		expect(logger.warn).not.toHaveBeenCalled();
	});
});
