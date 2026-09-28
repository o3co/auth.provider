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
 * `POST /session/login` asks before anything is written (the
 * session-admission ADR's D5, build order A6).
 *
 * Once the Store's `authenticate` succeeds, the route builds the primary with
 * core's `passwordPrimary` and calls `admitPrimary`; each outcome's answer is
 * pinned here: `establish` → the session established as it always was;
 * `unavailable` → `503`, logged once by admission, nothing written;
 * `interrupt` → the express session regenerated and left unauthenticated, the
 * requirement's ceremony opened with the regenerated session's id, the session
 * saved, and the requirement's validated `403` answered with a fresh CSRF
 * token — and each point that can fail after the regeneration (the
 * regeneration itself, `open`, the save) answered `503` with the cookie
 * session dropped, no `UserSession`, and the session never established.
 *
 * The express session is express-session's own over its `MemoryStore`, so the
 * regeneration mints a real session id, the save is a real store write, and a
 * dropped session sets no cookie. That no requirement changes the login — the
 * route with none registered — is `Session.test.mts`'s, unchanged.
 */

import type {
	Logger,
	PrimaryAuthentication,
	PrimaryContinuation,
	SessionRequirement,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import session, { MemoryStore } from "express-session";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createCsrfProtection } from "#/csrf.mjs";
import { createRouter } from "#/routes/Session.mjs";

const config = {
	cors: { allowedOrigins: [] },
	rateLimit: { login: { windowMs: 60_000, limit: 100 } },
	session: {
		secret: "test-session-secret",
		name: "auth.session",
		secure: false,
		sameSite: "lax",
		domain: null,
		redirectAllowlist: ["https://app.example.com/after"],
	},
} as never;

const csrf = createCsrfProtection({
	secret: "test-session-secret",
	cookieName: "auth.session.csrf",
});
const csrfToken = csrf.mint();

const SESSION_COOKIE = "login.sid";

const SESSION_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};

/** The user the Store verifies. */
const ALICE = {
	id: "u-1",
	username: "alice",
	email: "alice@example.com",
	name: "Alice",
	groups: ["staff"],
	locale: "en",
};

/** The body the fixture requirement answers a login it interrupts with: core's closed shape. */
const INTERRUPTION = {
	status: 403 as const,
	body: { error: "fixture_required", transaction: "dHgtMQ", expires_in: 600, hints: { step: 1 } },
};

/** A logger whose every level is a spy; `child` answers the same logger. */
function spyLogger() {
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
}

type SpyLogger = ReturnType<typeof spyLogger>;

/** The error lines logged, by event name. */
const errorEvents = (logger: SpyLogger): string[] =>
	logger.error.mock.calls.map((call) => call[1] as string);

/** A requirement named `fixture`, answering `answer` at establishment and recording what it was asked. */
function fixture(
	answer: (primary: PrimaryAuthentication) => "establish" | Error | "interrupt",
	open: (sessionId: string, continuation: PrimaryContinuation) => Promise<unknown> = async () =>
		INTERRUPTION,
) {
	const asked: PrimaryAuthentication[] = [];
	const opened: { sessionId: string; continuation: PrimaryContinuation }[] = [];
	const trace: string[] = [];
	const requirement: SessionRequirement = {
		name: "fixture",
		reach: new Set<string>(),
		stepUpPage: undefined,
		remediations: [],
		hintKeys: ["step"],
		admit: async () => ({ outcome: "met" }),
		admitPrimary: async (primary) => {
			asked.push(primary);
			const verdict = answer(primary);
			if (verdict instanceof Error) throw verdict;
			if (verdict === "establish") return "establish";
			return {
				open: async (sessionId, continuation) => {
					trace.push("open");
					opened.push({ sessionId, continuation });
					return (await open(sessionId, continuation)) as never;
				},
			};
		},
	};
	return { requirement, asked, opened, trace };
}

interface Setup {
	readonly requirements?: readonly SessionRequirement[];
	/** The trace the store writes land on, beside the requirement's `open`. */
	readonly trace?: string[];
	/** The cookie store's `destroy` — express-session's regeneration — fails. */
	readonly regenerateError?: Error;
	/** The cookie store's `set` — the route's save — fails. */
	readonly saveError?: Error;
	readonly logger?: SpyLogger;
	/** The user the Store verifies alice as; `ALICE` by default. */
	readonly user?: Record<string, unknown>;
}

/**
 * The login router behind express-session over a `MemoryStore` whose
 * `destroy` and `set` join `trace` and fail where the setup says; a
 * `UserSessionStore` and a `SubjectSessionIndex` whose writes join it too.
 */
function setup(options: Setup = {}) {
	const trace = options.trace ?? [];
	const cookieStore = new MemoryStore();
	const destroy = cookieStore.destroy.bind(cookieStore);
	const set = cookieStore.set.bind(cookieStore);
	cookieStore.destroy = (sid, cb) => {
		trace.push("regenerate");
		if (options.regenerateError) {
			cb?.(options.regenerateError);
			return;
		}
		destroy(sid, cb);
	};
	cookieStore.set = (sid, data, cb) => {
		trace.push("save");
		if (options.saveError) {
			cb?.(options.saveError);
			return;
		}
		set(sid, data, cb);
	};
	const userSessionStore = {
		kind: "memory",
		create: vi.fn(async () => {
			trace.push("create");
		}),
		get: vi.fn(async () => null),
		delete: vi.fn(async () => {}),
	} as unknown as UserSessionStore & { create: ReturnType<typeof vi.fn> };
	const subjectSessionIndex = {
		kind: "memory",
		addSid: vi.fn(async () => {}),
		listSids: vi.fn(async () => []),
		removeSid: vi.fn(async () => {}),
		removeBySubject: vi.fn(async () => {}),
	};
	const userRepository = {
		authenticate: vi.fn(async (username: string, password: string) =>
			username === "alice" && password === "secret" ? (options.user ?? ALICE) : null,
		),
		authenticateByToken: vi.fn(async () => null),
	} as unknown as UserRepository;
	const logger = options.logger ?? spyLogger();

	const app = express();
	app.use(
		session({
			name: SESSION_COOKIE,
			secret: "cookie-secret",
			resave: false,
			saveUninitialized: false,
			store: cookieStore,
		}),
	);
	app.use(
		"/session",
		createRouter(express, {
			userRepository,
			config,
			userSessionStore,
			subjectSessionIndex: subjectSessionIndex as never,
			csrf,
			logger: logger as unknown as Logger,
			requirements: resolverForTests(options.requirements ?? []),
		}),
	);
	return { app, cookieStore, userSessionStore, subjectSessionIndex, logger, trace };
}

const login = (app: express.Express, body: Record<string, string> = {}) =>
	request(app)
		.post("/session/login")
		.set("Cookie", `${csrf.cookieName}=${csrfToken}`)
		.set(csrf.headerName, csrfToken)
		.set("User-Agent", "login-admission-test/1")
		.type("json")
		.send({ username: "alice", password: "secret", ...body });

/**
 * The trace up to the route's own save. express-session saves a regenerated
 * session once more as the response ends — the route's explicit save does not
 * mark it saved — so what follows the route's writes is that save alone.
 */
function routeWrites(trace: readonly string[], length: number): readonly string[] {
	expect(trace.slice(length).every((entry) => entry === "save")).toBe(true);
	return trace.slice(0, length);
}

/** The response's `Set-Cookie` values. */
const setCookies = (res: request.Response): string[] =>
	(res.headers["set-cookie"] as unknown as string[] | undefined) ?? [];

/** The session id the response's session cookie names, or `undefined` when it sets none. */
function cookieSessionId(res: request.Response): string | undefined {
	const cookie = setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`));
	if (cookie === undefined) return undefined;
	const value = decodeURIComponent(cookie.slice(SESSION_COOKIE.length + 1).split(";")[0] ?? "");
	// express-session signs it: `s:<id>.<signature>`.
	return value.slice(2, value.lastIndexOf("."));
}

/** What the cookie store holds under `sid`, parsed. */
function stored(cookieStore: MemoryStore, sid: string): Record<string, unknown> | undefined {
	const sessions = (cookieStore as unknown as { sessions: Record<string, string> }).sessions;
	const raw = sessions[sid];
	return raw === undefined ? undefined : (JSON.parse(raw) as Record<string, unknown>);
}

/** Every session the cookie store holds. */
const storedSessions = (cookieStore: MemoryStore): Record<string, string> =>
	(cookieStore as unknown as { sessions: Record<string, string> }).sessions;

// ---------------------------------------------------------------------------
// The router takes the resolver
// ---------------------------------------------------------------------------

describe("the session router takes the session requirements (the session-admission ADR's D1)", () => {
	it("throws at construction without requirements", () => {
		expect(() =>
			createRouter(express, {
				userRepository: {} as UserRepository,
				config,
				csrf,
				logger: spyLogger() as unknown as Logger,
				requirements: undefined as never,
			}),
		).toThrow("session routes require requirements");
	});
});

// ---------------------------------------------------------------------------
// establish
// ---------------------------------------------------------------------------

describe("POST /session/login — every requirement answers establish", () => {
	it("asks each requirement once about the primary passwordPrimary built from the route's facts, before anything is written", async () => {
		const trace: string[] = [];
		const { requirement, asked } = fixture(() => {
			trace.push("asked");
			return "establish";
		});
		const { app } = setup({ requirements: [requirement], trace });
		const before = Date.now();

		const res = await login(app, { redirect_to: "https://app.example.com/after" });

		expect(res.status).toBe(200);
		expect(asked).toHaveLength(1);
		const [primary] = asked;
		expect(primary?.subject).toBe("u-1");
		expect(primary?.user).toEqual(ALICE);
		// `extractUserClaims(user)`: the claims the record will hold.
		expect(primary?.claims).toEqual({
			email: "alice@example.com",
			name: "Alice",
			groups: ["staff"],
		});
		expect(primary?.recorded).toEqual({
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
		expect(primary?.authTime.getTime()).toBeGreaterThanOrEqual(before);
		expect(primary?.authTime.getTime()).toBeLessThanOrEqual(Date.now());
		expect(primary?.redirectTo).toBe("https://app.example.com/after");
		expect(primary?.request.userAgent).toBe("login-admission-test/1");
		expect(typeof primary?.request.ip).toBe("string");
		// Asked before the record, the regeneration and the save.
		expect(routeWrites(trace, 4)).toEqual(["asked", "create", "regenerate", "save"]);
	});

	it("establishes the session from what admission established: the record's authTime is the primary's, and the session is authenticated", async () => {
		const { requirement, asked } = fixture(() => "establish");
		const { app, userSessionStore, cookieStore } = setup({ requirements: [requirement] });

		const res = await login(app, { redirect_to: "https://app.example.com/after" });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully" });
		expect(userSessionStore.create).toHaveBeenCalledTimes(1);
		const created = userSessionStore.create.mock.calls[0]?.[0] as Record<string, unknown>;
		expect(created).toMatchObject({
			sub: "u-1",
			authTime: asked[0]?.authTime,
			claims: { email: "alice@example.com", name: "Alice", groups: ["staff"] },
			amr: ["pwd"],
		});
		const sid = cookieSessionId(res);
		expect(sid).toBeDefined();
		expect(stored(cookieStore, sid as string)).toMatchObject({
			isAuthenticated: true,
			user: ALICE,
			sid: created.sid,
			redirectTo: "https://app.example.com/after",
		});
		expect(setCookies(res).some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
	});

	it("does not ask when the credentials are refused, missing, or the Store cannot answer", async () => {
		const { requirement, asked } = fixture(() => "establish");
		const { app } = setup({ requirements: [requirement] });

		expect((await login(app, { password: "wrong" })).status).toBe(401);
		expect((await login(app, { password: "" })).status).toBe(400);
		expect(asked).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// A primary core cannot build
// ---------------------------------------------------------------------------

describe("POST /session/login — a user core cannot copy into the primary", () => {
	it("is refused before any requirement is asked and before anything is written: the route's error, answered 500", async () => {
		// `passwordPrimary` holds a structured-clone copy of the user, so a
		// value that cannot be copied — a function — is a RangeError there.
		// Before admission the express session's JSON store dropped it and
		// the login succeeded.
		const { requirement, asked } = fixture(() => "establish");
		const { app, userSessionStore, trace } = setup({
			requirements: [requirement],
			user: { ...ALICE, greet: () => "hello" },
		});

		const res = await login(app);

		expect(res.status).toBe(500);
		expect(asked).toEqual([]);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(trace).toEqual([]);
		expect(cookieSessionId(res)).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// unavailable
// ---------------------------------------------------------------------------

describe("POST /session/login — admission answers unavailable", () => {
	it("answers 503, logged once by admission, and writes nothing: no record, no regeneration, no save, no cookie", async () => {
		const { requirement } = fixture(() => new Error("requirement store down"));
		const { app, userSessionStore, logger, trace, cookieStore } = setup({
			requirements: [requirement],
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(trace).toEqual([]);
		expect(cookieSessionId(res)).toBeUndefined();
		expect(Object.keys(storedSessions(cookieStore))).toEqual([]);
		expect(errorEvents(logger)).toEqual(["session_admission_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			store: "fixture",
			phase: "establishment",
		});
	});
});

// ---------------------------------------------------------------------------
// interrupt
// ---------------------------------------------------------------------------

describe("POST /session/login — a requirement interrupts", () => {
	it("regenerates the express session, opens the ceremony with the regenerated session's id, saves it, and answers the requirement's 403 — in that order", async () => {
		const { requirement, trace } = fixture(() => "interrupt");
		const { app } = setup({ requirements: [requirement], trace });

		const res = await login(app);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(INTERRUPTION.body);
		expect(routeWrites(trace, 3)).toEqual(["regenerate", "open", "save"]);
	});

	it("binds the ceremony to the regenerated session, which the store holds unauthenticated and the cookie names", async () => {
		const { requirement, opened } = fixture(() => "interrupt");
		const { app, cookieStore } = setup({ requirements: [requirement] });

		const res = await login(app, { redirect_to: "https://app.example.com/after" });

		expect(res.status).toBe(403);
		expect(opened).toHaveLength(1);
		const [{ sessionId, continuation }] = opened as [(typeof opened)[number]];
		expect(cookieSessionId(res)).toBe(sessionId);
		const held = stored(cookieStore, sessionId);
		expect(held).toBeDefined();
		for (const field of ["isAuthenticated", "user", "sid", "redirectTo"]) {
			expect(held, field).not.toHaveProperty(field);
		}
		// What the requirement persists: the primary as the route built it,
		// the redirect with it, and nothing completed yet.
		expect(continuation).toMatchObject({
			interruptedBy: "fixture",
			done: [],
			primary: {
				subject: "u-1",
				user: ALICE,
				claims: { email: "alice@example.com", name: "Alice", groups: ["staff"] },
				recorded: { amr: ["pwd"] },
				redirectTo: "https://app.example.com/after",
			},
		});
	});

	it("writes no UserSession and no index entry, and issues a fresh CSRF token with the 403", async () => {
		const { requirement } = fixture(() => "interrupt");
		const { app, userSessionStore, subjectSessionIndex, logger } = setup({
			requirements: [requirement],
		});

		const res = await login(app);

		expect(res.status).toBe(403);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(subjectSessionIndex.addSid).not.toHaveBeenCalled();
		expect(setCookies(res).some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("a regeneration that fails: 503, logged once, the ceremony never opened, the cookie session dropped", async () => {
		const { requirement, opened } = fixture(() => "interrupt");
		const { app, userSessionStore, logger, trace, cookieStore } = setup({
			requirements: [requirement],
			regenerateError: new Error("cookie store down"),
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(opened).toEqual([]);
		expect(trace).toEqual(["regenerate"]);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(cookieSessionId(res)).toBeUndefined();
		expect(Object.keys(storedSessions(cookieStore))).toEqual([]);
		expect(errorEvents(logger)).toEqual(["login_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			store: "cookie_session",
			step: "regenerate",
		});
	});

	it("an open that throws after the regeneration: 503, logged once naming the requirement, never saved, the cookie session dropped, no UserSession", async () => {
		const { requirement, trace } = fixture(
			() => "interrupt",
			async () => {
				throw new Error("the requirement's record could not be written");
			},
		);
		const { app, userSessionStore, logger, cookieStore } = setup({
			requirements: [requirement],
			trace,
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(trace).toEqual(["regenerate", "open"]);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(cookieSessionId(res)).toBeUndefined();
		expect(Object.keys(storedSessions(cookieStore))).toEqual([]);
		expect(errorEvents(logger)).toEqual(["login_store_unavailable"]);
		const [line] = logger.error.mock.calls[0] as [Record<string, unknown>];
		expect(line).toMatchObject({ store: "fixture", step: "open" });
		expect(line.err).not.toBeInstanceOf(Error);
	});

	it("an answer core refuses — a body outside the closed shape — is an open failure: 503, the cookie session dropped", async () => {
		const { requirement } = fixture(
			() => "interrupt",
			async () => ({ status: 403, body: { error: "fixture_required", user: ALICE } }),
		);
		const { app, userSessionStore, logger } = setup({ requirements: [requirement] });

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(JSON.stringify(res.body)).not.toContain("alice");
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(cookieSessionId(res)).toBeUndefined();
		expect(errorEvents(logger)).toEqual(["login_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store: "fixture", step: "open" });
	});

	it("a save that fails after open: 503, logged once, the cookie session dropped, no UserSession — the requirement's record left to its own expiry", async () => {
		const { requirement, trace, opened } = fixture(() => "interrupt");
		const { app, userSessionStore, logger } = setup({
			requirements: [requirement],
			trace,
			saveError: new Error("cookie store down"),
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(trace).toEqual(["regenerate", "open", "save"]);
		expect(opened).toHaveLength(1);
		expect(userSessionStore.create).not.toHaveBeenCalled();
		expect(cookieSessionId(res)).toBeUndefined();
		expect(errorEvents(logger)).toEqual(["login_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			store: "cookie_session",
			step: "save",
		});
	});
});
