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
 * `POST /session/login` asks before anything is written (ADR
 * 2026-09-28-session-admission, D5): once the Store's `authenticate`
 * succeeds, the route builds the primary with core's `passwordPrimary` and
 * calls `admitPrimary`. Each outcome's answer is pinned here.
 *
 * The express session is express-session's own over its `MemoryStore`, so the
 * regeneration mints a real session id, the save is a real store write, and a
 * dropped session sets no cookie. The route with no requirement registered is
 * pinned by `Session.test.mts`.
 */

import {
	type AdmissionDeps,
	admitPrimary,
	type Logger,
	type PrimaryAuthentication,
	type PrimaryContinuation,
	passwordPrimary,
	type SessionRequirement,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestCsrfTokenSigner, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import session, { MemoryStore } from "express-session";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	type AnswerInterruptionResult,
	answerInterruption,
	type InterruptionReporter,
} from "#/answer-interruption.mjs";
import { createCsrfProtection } from "#/csrf.mjs";
import { createRouter } from "#/routes/Session.mjs";

/** The session module's section, as the router receives it. */
const section = {
	rateLimit: { login: { windowMs: 60_000, limit: 100 } },
	redirectAllowlist: ["https://app.example.com/after"],
};

/** The session cookie, as the `sessionCookiePolicy` slot carries it. */
const sessionCookie = {
	name: "auth.session",
	secure: false,
	sameSite: "lax",
	domain: undefined,
} as const;

/** The signer the router is given, and a protection over it that mints the tokens these requests carry. */
const SIGNER = createTestCsrfTokenSigner();
const csrf = createCsrfProtection({
	signer: SIGNER,
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

/** What the session holds of `ALICE`: the fields `User` declares, nothing else of the Store's. */
const { locale: _notCarried, ...ALICE_SNAPSHOT } = ALICE;

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
 * A `MemoryStore` whose `destroy` — express-session's regeneration — and
 * `set` — a save — join `trace` and fail where `options` says.
 */
function tracedCookieStore(
	trace: string[],
	options: Pick<Setup, "regenerateError" | "saveError">,
): MemoryStore {
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
	return cookieStore;
}

/** express-session over `cookieStore`, as the tests mount it. */
const cookieSession = (cookieStore: MemoryStore) =>
	session({
		name: SESSION_COOKIE,
		secret: "cookie-secret",
		resave: false,
		saveUninitialized: false,
		store: cookieStore,
	});

/**
 * The login router behind express-session over a `MemoryStore` whose
 * `destroy` and `set` join `trace` and fail where the setup says; a
 * `UserSessionStore` and a `SubjectSessionIndex` whose writes join it too.
 */
function setup(options: Setup = {}) {
	const trace = options.trace ?? [];
	const cookieStore = tracedCookieStore(trace, options);
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
		authenticate: vi.fn(async (username: string, password: string) => {
			if (username === "directory-down") throw new Error("user directory down");
			return username === "alice" && password === "secret" ? (options.user ?? ALICE) : null;
		}),
		authenticateByToken: vi.fn(async () => null),
	} as unknown as UserRepository;
	const logger = options.logger ?? spyLogger();

	const app = express();
	app.use(cookieSession(cookieStore));
	app.use(
		"/session",
		createRouter(express, {
			csrfTokenSigner: SIGNER,
			userRepository,
			section,
			sessionCookie,
			deploymentMode: "unset",
			userSessionStore,
			subjectSessionIndex: subjectSessionIndex as never,
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

describe("the session router takes the session requirements", () => {
	it("throws at construction without requirements", () => {
		expect(() =>
			createRouter(express, {
				csrfTokenSigner: SIGNER,
				userRepository: {} as UserRepository,
				section,
				sessionCookie,
				deploymentMode: "unset",
				logger: spyLogger() as unknown as Logger,
				requirements: undefined as never,
			}),
		).toThrow(/^session routes: requirements is required/);
	});

	it("throws at construction with a resolver the planner did not build: a forged one never reaches a login", () => {
		const forged = { get: () => undefined, entries: () => [][Symbol.iterator]() };
		expect(() =>
			createRouter(express, {
				csrfTokenSigner: SIGNER,
				userRepository: {} as UserRepository,
				section,
				sessionCookie,
				deploymentMode: "unset",
				logger: spyLogger() as unknown as Logger,
				requirements: forged as never,
			}),
		).toThrow(
			/^session routes: requirements must be the sessionRequirementResolver the boot planner built/,
		);
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
		expect(primary?.user).toStrictEqual(ALICE_SNAPSHOT);
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
			user: ALICE_SNAPSHOT,
			sid: created.sid,
			redirectTo: "https://app.example.com/after",
		});
		// Exactly the declared fields: the Store's `locale` is not carried.
		expect((stored(cookieStore, sid as string) as { user: unknown }).user).toStrictEqual(
			ALICE_SNAPSHOT,
		);
		expect(setCookies(res).some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
	});

	it("does not ask when the credentials are refused, missing, or the Store cannot answer", async () => {
		const { requirement, asked } = fixture(() => "establish");
		const { app } = setup({ requirements: [requirement] });

		expect((await login(app, { password: "wrong" })).status).toBe(401);
		expect((await login(app, { password: "" })).status).toBe(400);
		expect((await login(app, { username: "directory-down" })).status).toBe(503);
		expect(asked).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// A primary core cannot build
// ---------------------------------------------------------------------------

describe("POST /session/login — a user whose field the login needs is not plain data", () => {
	it("is refused before any requirement is asked and before anything is written: the route's error, answered 500", async () => {
		// The route reads the user once with core's `readUserSnapshot`: a
		// field the login needs that is not plain data — a witness that is a
		// Date — is refused there, since left out it would read as not enrolled.
		const { requirement, asked } = fixture(() => "establish");
		const { app, userSessionStore, trace } = setup({
			requirements: [requirement],
			user: { ...ALICE, mfaEnrolled: new Date(0) },
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
// The User is read once
// ---------------------------------------------------------------------------

/** `fields` as a class instance's prototype getters, each counting its reads by name. */
function countingUser(fields: Record<string, unknown>): {
	user: Record<string, unknown>;
	reads: Map<string, number>;
} {
	const reads = new Map<string, number>();
	class Entity {}
	for (const [name, value] of Object.entries(fields)) {
		Object.defineProperty(Entity.prototype, name, {
			get() {
				reads.set(name, (reads.get(name) ?? 0) + 1);
				return value;
			},
			configurable: true,
		});
	}
	return { user: new Entity() as Record<string, unknown>, reads };
}

describe("POST /session/login — the User the Store answers is read once", () => {
	it("runs each of a getter-backed User's getters exactly once, and the session's subject and claims are the snapshot's", async () => {
		const { requirement, asked } = fixture(() => "establish");
		const { user, reads } = countingUser({ ...ALICE, emailVerified: true, mfaEnrolled: false });
		const { app, userSessionStore } = setup({ requirements: [requirement], user });

		const res = await login(app);

		expect(res.status).toBe(200);
		for (const field of [
			"id",
			"username",
			"email",
			"emailVerified",
			"name",
			"groups",
			"mfaEnrolled",
		]) {
			expect(reads.get(field), field).toBe(1);
		}
		expect(reads.has("locale")).toBe(false);
		expect(asked[0]).toMatchObject({
			subject: "u-1",
			claims: {
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				groups: ["staff"],
			},
		});
		expect(userSessionStore.create).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// unavailable
// ---------------------------------------------------------------------------

describe("POST /session/login — admission answers unavailable", () => {
	it("answers 503, described as the requirement's outage — the only one admitPrimary reports — logged once by admission, and writes nothing: no record, no regeneration, no save, no cookie", async () => {
		const { requirement } = fixture(() => new Error("requirement store down"));
		const { app, userSessionStore, logger, trace, cookieStore } = setup({
			requirements: [requirement],
		});

		const res = await login(app);

		expect(res.status).toBe(503);
		// Core's describeAdmissionOutage: never the session store's words.
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session requirement unavailable",
		});
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
				user: ALICE_SNAPSHOT,
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

// ---------------------------------------------------------------------------
// answerInterruption — the interruption's answer, exported for a requirement's
// completion (the MFA package's, after `resumePrimary` interrupts again)
// ---------------------------------------------------------------------------

describe("answerInterruption — the login's interruption answer, exported", () => {
	/**
	 * A route, behind express-session over a traced `MemoryStore`, that has
	 * `admitPrimary` interrupt through `requirement` and hands the admission to
	 * `answerInterruption` with a reporter recording what it is told — as a
	 * requirement's completion route does with what `resumePrimary` answered.
	 */
	function helperApp(
		requirement: SessionRequirement,
		options: Pick<Setup, "regenerateError" | "saveError" | "trace"> = {},
	) {
		const trace = options.trace ?? [];
		const cookieStore = tracedCookieStore(trace, options);
		const reported: [string, string, unknown][] = [];
		const reporter: InterruptionReporter = {
			storeUnavailable: (store, step, cause) => {
				reported.push([store, step, cause]);
			},
		};
		const results: AnswerInterruptionResult[] = [];
		const deps: AdmissionDeps = {
			userSessionStore: undefined,
			subjectRevocation: undefined,
			requirements: resolverForTests([requirement]),
			acrTable: {},
			logger: undefined,
			auditSink: undefined,
		};
		const app = express();
		app.use(cookieSession(cookieStore));
		app.post("/complete", async (req, res) => {
			const admission = await admitPrimary(
				deps,
				passwordPrimary({
					subject: ALICE.id,
					user: ALICE,
					claims: {},
					authTime: new Date(),
					redirectTo: undefined,
					request: {},
				}),
			);
			if (admission.outcome !== "interrupt") throw new Error("expected an interruption");
			results.push(await answerInterruption(admission, { req, res, csrf, reporter }));
		});
		return { app, trace, reported, results, cookieStore };
	}

	it("is exported from the package, beside establishSession", async () => {
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		expect(mod.answerInterruption).toBe(answerInterruption);
	});

	it("regenerates, opens the ceremony with the regenerated session's id, saves, and answers the requirement's 403 with a fresh CSRF token", async () => {
		const { requirement, trace, opened } = fixture(() => "interrupt");
		const helper = helperApp(requirement, { trace });

		const res = await request(helper.app).post("/complete");

		expect(res.status).toBe(403);
		expect(res.body).toEqual(INTERRUPTION.body);
		expect(routeWrites(trace, 3)).toEqual(["regenerate", "open", "save"]);
		expect(opened[0]?.sessionId).toBe(cookieSessionId(res));
		expect(setCookies(res).some((c) => c.startsWith(`${csrf.cookieName}=`))).toBe(true);
		expect(helper.results).toEqual([{ outcome: "answered" }]);
		expect(helper.reported).toEqual([]);
	});

	it("each failure after the regeneration: 503, told to the reporter once, the cookie session dropped — and the outcome names the store and the step", async () => {
		const down = new Error("store down");
		const cases = [
			{
				label: "the regeneration",
				requirement: fixture(() => "interrupt").requirement,
				options: { regenerateError: down },
				store: "cookie_session",
				step: "regenerate",
			},
			{
				label: "open",
				requirement: fixture(
					() => "interrupt",
					async () => {
						throw down;
					},
				).requirement,
				options: {},
				store: "fixture",
				step: "open",
			},
			{
				label: "the save",
				requirement: fixture(() => "interrupt").requirement,
				options: { saveError: down },
				store: "cookie_session",
				step: "save",
			},
		] as const;
		for (const { label, requirement, options, store, step } of cases) {
			const helper = helperApp(requirement, options);

			const res = await request(helper.app).post("/complete");

			expect(res.status, label).toBe(503);
			expect(res.body, label).toEqual(SESSION_STORE_UNAVAILABLE);
			expect(cookieSessionId(res), label).toBeUndefined();
			expect(
				setCookies(res).some((c) => c.startsWith(`${csrf.cookieName}=`)),
				label,
			).toBe(false);
			expect(helper.reported, label).toEqual([[store, step, down]]);
			expect(helper.results, label).toEqual([{ outcome: "unavailable", store, step }]);
		}
	});

	it("refuses what is not an interruption admission answered, with a RangeError, before the session is touched", async () => {
		const trace: string[] = [];
		const cookieStore = tracedCookieStore(trace, {});
		const app = express();
		app.use(cookieSession(cookieStore));
		const thrown: unknown[] = [];
		let opened = 0;
		const open = async () => {
			opened += 1;
			return INTERRUPTION;
		};
		app.post("/complete", async (req, res) => {
			for (const admission of [
				{ outcome: "establish" },
				// Shaped like an interruption but answered as another outcome.
				{ outcome: "establish", requirement: "fixture", open },
				{ outcome: "unavailable", store: "fixture", open },
				{ outcome: "interrupt", requirement: "fixture" },
				undefined,
			]) {
				try {
					await answerInterruption(admission as never, {
						req,
						res,
						csrf,
						reporter: { storeUnavailable: () => {} },
					});
				} catch (err) {
					thrown.push(err);
				}
			}
			res.status(204).end();
		});

		const res = await request(app).post("/complete");

		expect(res.status).toBe(204);
		expect(thrown).toHaveLength(5);
		for (const err of thrown) expect(err).toBeInstanceOf(RangeError);
		expect(trace).toEqual([]);
		expect(opened).toBe(0);
	});
});

describe("answerInterruption — an interruption core did not build", () => {
	it("refuses a copy of a genuine interruption, and an object shaped like one, with a RangeError, before the session is touched and without opening", async () => {
		const { requirement, trace, opened } = fixture(() => "interrupt");
		const cookieStore = tracedCookieStore(trace, {});
		const deps: AdmissionDeps = {
			userSessionStore: undefined,
			subjectRevocation: undefined,
			requirements: resolverForTests([requirement]),
			acrTable: {},
			logger: undefined,
			auditSink: undefined,
		};
		const app = express();
		app.use(cookieSession(cookieStore));
		const thrown: unknown[] = [];
		app.post("/complete", async (req, res) => {
			const genuine = await admitPrimary(
				deps,
				passwordPrimary({
					subject: ALICE.id,
					user: ALICE,
					claims: {},
					authTime: new Date(),
					redirectTo: undefined,
					request: {},
				}),
			);
			if (genuine.outcome !== "interrupt") throw new Error("expected an interruption");
			for (const forged of [
				{ ...genuine },
				{
					outcome: "interrupt",
					requirement: genuine.requirement,
					continuation: genuine.continuation,
					open: genuine.open,
				},
			]) {
				try {
					await answerInterruption(forged as never, {
						req,
						res,
						csrf,
						reporter: { storeUnavailable: () => {} },
					});
				} catch (err) {
					thrown.push(err);
				}
			}
			res.status(204).end();
		});

		const res = await request(app).post("/complete");

		expect(res.status).toBe(204);
		expect(thrown).toHaveLength(2);
		for (const err of thrown) expect(err).toBeInstanceOf(RangeError);
		expect(trace).toEqual([]);
		expect(opened).toEqual([]);
	});
});
