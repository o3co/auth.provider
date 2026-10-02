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
 * `admitSession` (the session-admission ADR's D2, D4, D10): the claim
 * builders, the seven steps in order and fail-closed, the graded action and
 * the `remediation` rule, the two log lines, the audit event, and the brands
 * a caller cannot forge. The merge's rows are `admit.merge.test.mts`.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import type { AdmissionAction } from "#/session-admission/actions.mjs";
import {
	admitSession,
	checkResolver,
	codeClaimFirstRead,
	codeClaimRevalidation,
	cookieClaim,
	cookieSessionUser,
	linkClaim,
	passwordPrimary,
	tokenClaim,
	viewOf,
} from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	AdmissionRequest,
	IssuedRemediationAction,
	RequirementInput,
	SessionClaim,
	SessionRequirement,
	SessionRequirementResolver,
} from "#/session-admission/requirement.mjs";
import { issuedRemediationActions } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { SubjectRevocation, UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");
/** The issuer each resolver here registers its pages on. */
const ISSUER = "https://auth.test";
const minutesAgo = (minutes: number): Date => new Date(NOW.getTime() - minutes * 60_000);

const session = (over: Partial<UserSession> = {}): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(NOW.getTime() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

const storeOf = (
	answer: (sid: string) => Promise<UserSession | null | undefined>,
): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: answer as UserSessionStore["get"],
	delete: async () => {},
});

const holding = (record: UserSession): UserSessionStore =>
	storeOf(async (sid) => (sid === record.sid ? record : null));

const revocationOf = (answer: (subject: string) => Promise<unknown>): SubjectRevocation => ({
	kind: "test",
	revokeBefore: async () => {},
	revokedBefore: answer as SubjectRevocation["revokedBefore"],
});

interface Line {
	readonly level: "info" | "warn" | "error";
	readonly fields: Record<string, unknown>;
	readonly message: string | undefined;
}

const recordingLogger = (): { readonly logger: Logger; readonly lines: Line[] } => {
	const lines: Line[] = [];
	const at =
		(level: Line["level"]) =>
		(first: unknown, second?: unknown): void => {
			lines.push({
				level,
				fields:
					typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {},
				message: typeof first === "string" ? first : (second as string | undefined),
			});
		};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
};

const recordingSink = (): { readonly sink: AuditSink; readonly events: AuditEvent[] } => {
	const events: AuditEvent[] = [];
	return {
		sink: {
			kind: "test",
			record: async (event) => {
				events.push(event);
			},
		},
		events,
	};
};

const cookie = (over: Record<string, unknown> = {}): SessionClaim =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" }, ...over },
	});

const met = (name: string, over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name,
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

const deps = (over: Partial<AdmissionDeps> = {}): AdmissionDeps => ({
	userSessionStore: holding(session()),
	subjectRevocation: undefined,
	requirements: resolverForTests([], { actions: TEST_ACTIONS }),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
	now: () => NOW,
	...over,
});

/** A resolver over reaching non-mfa fixtures: a test of admission's own mechanics, the reach rules boot holds lifted. */
const anyReach = (requirements: SessionRequirement[]) =>
	resolverForTests(requirements, { allowAnyReach: true, issuer: ISSUER, actions: TEST_ACTIONS });

const request = (over: Partial<AdmissionRequest> = {}): AdmissionRequest => ({
	claim: cookie(),
	action: "test.use",
	...over,
});

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("the claim builders — one reading of each carrier", () => {
	it("reads a cookie: authenticated only when isAuthenticated is exactly true, sid and user.id when they are non-empty strings", () => {
		expect(cookie()).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "cookie",
		});
		for (const flag of [1, "true", undefined, null, {}]) {
			expect(cookie({ isAuthenticated: flag }).authenticated, String(flag)).toBe(false);
		}
		for (const sid of ["", 7, null, undefined]) {
			expect(cookie({ sid }).sid, String(sid)).toBeUndefined();
		}
		for (const user of [undefined, null, {}, { id: "" }, { id: 7 }, "user-1"]) {
			expect(cookie({ user }).subject, JSON.stringify(user)).toBeUndefined();
		}
		expect(cookieClaim({ session: undefined })).toMatchObject({
			authenticated: false,
			sid: undefined,
			subject: undefined,
		});
		expect(cookieClaim({})).toMatchObject({ authenticated: false });
	});

	it("reads a code record twice, by two builders: the first read without a subject, the revalidation with the first read's — required, so the comparison cannot be left out", () => {
		expect(codeClaimFirstRead({ sid: "sid-1" })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: undefined,
			carrier: "code",
		});
		expect(codeClaimRevalidation({ sid: "sid-1" }, "user-1")).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "code",
		});
		expect(codeClaimFirstRead({}).sid).toBeUndefined();
		expect(codeClaimFirstRead({ sid: "" }).sid).toBeUndefined();
		for (const subject of [undefined, "", 7, null, ["user-1"]]) {
			expect(
				() => codeClaimRevalidation({ sid: "sid-1" }, subject as never),
				JSON.stringify(subject),
			).toThrow(RangeError);
		}
	});

	it("reads a link transaction: authenticated, its sid and the subject recorded at the start", () => {
		expect(linkClaim({ sid: "sid-1", subject: "user-1" })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "link",
		});
	});

	it("reads a verified token: authenticated, its sid when it carries one, its sub, and its amr when well formed", () => {
		expect(tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["pwd", "otp", "mfa"] })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "token",
			tokenAmr: ["pwd", "otp", "mfa"],
		});
		expect(tokenClaim({ sub: "user-1" })).toMatchObject({ sid: undefined, subject: "user-1" });
		expect(tokenClaim({ sub: "user-1" })).not.toHaveProperty("tokenAmr");
		// A token without an amr, or one whose amr is not a well-formed list.
		for (const amr of [undefined, [], [""], "pwd", [1]]) {
			expect(tokenClaim({ sub: "user-1", amr }), JSON.stringify(amr)).not.toHaveProperty(
				"tokenAmr",
			);
		}
		for (const sub of ["", 7, null, undefined, ["user-1"]]) {
			expect(() => tokenClaim({ sid: "sid-1", sub }), JSON.stringify(sub)).toThrow(RangeError);
		}
		expect(() => tokenClaim({ sid: "sid-1" } as never)).toThrow(RangeError);
	});

	it("refuses, before anything is read, what is not a carrier: a caller's fault is a RangeError", () => {
		for (const bad of [undefined, null, "cookie", 7]) {
			expect(() => cookieClaim(bad as never), String(bad)).toThrow(RangeError);
			expect(() => codeClaimFirstRead(bad as never), String(bad)).toThrow(RangeError);
			expect(() => codeClaimRevalidation(bad as never, "user-1"), String(bad)).toThrow(RangeError);
			expect(() => linkClaim(bad as never), String(bad)).toThrow(RangeError);
			expect(() => tokenClaim(bad as never), String(bad)).toThrow(RangeError);
		}
		expect(() => linkClaim({ sid: "", subject: "user-1" })).toThrow(RangeError);
		expect(() => linkClaim({ sid: "sid-1", subject: "" })).toThrow(RangeError);
	});

	it("answers a frozen claim", () => {
		expect(Object.isFrozen(cookie())).toBe(true);
		expect(Object.isFrozen(codeClaimFirstRead({ sid: "sid-1" }))).toBe(true);
		expect(Object.isFrozen(linkClaim({ sid: "sid-1", subject: "user-1" }))).toBe(true);
	});
});

describe("cookieSessionUser — the cookie session's user, for a route that admitted its subject", () => {
	const carrying = (over: Record<string, unknown> = {}) => ({
		session: {
			isAuthenticated: true,
			sid: "sid-1",
			user: { id: "user-1", email: "alice@example.com", groups: ["staff"] },
			...over,
		},
	});

	it("answers the user the cookie session holds when its id is the admitted subject", () => {
		expect(cookieSessionUser(carrying(), "user-1")).toEqual({
			id: "user-1",
			email: "alice@example.com",
			groups: ["staff"],
		});
	});

	it("answers a frozen copy that shares nothing with the session's user", () => {
		const req = carrying();
		const user = req.session.user as { groups: string[]; email: string };
		const answered = cookieSessionUser(req, "user-1");
		expect(answered).not.toBe(user);
		expect(Object.isFrozen(answered)).toBe(true);
		expect(Object.isFrozen(answered?.groups)).toBe(true);
		user.groups.push("admin");
		user.email = "mallory@example.com";
		expect(answered).toEqual({ id: "user-1", email: "alice@example.com", groups: ["staff"] });
	});

	it("answers nothing for a subject that is not the user's", () => {
		expect(cookieSessionUser(carrying(), "user-2")).toBeUndefined();
		expect(cookieSessionUser(carrying({ user: { id: "user-10" } }), "user-1")).toBeUndefined();
	});

	it.each([
		["no session", {}],
		["a session that is not authenticated", carrying({ isAuthenticated: false })],
		["a session whose flag is not exactly true", carrying({ isAuthenticated: "true" })],
		["no user", carrying({ user: undefined })],
		["a user without an id", carrying({ user: { email: "alice@example.com" } })],
		["a user whose id is not a string", carrying({ user: { id: 1 } })],
		["a user that is a list", carrying({ user: [{ id: "user-1" }] })],
		["a user that is a string", carrying({ user: "user-1" })],
		["a user whose email is a function", carrying({ user: { id: "user-1", email: () => "hi" } })],
		[
			"a user whose witness is a Date",
			carrying({ user: { id: "user-1", mfaEnrolled: new Date(0) } }),
		],
		["a user whose groups hold a Map", carrying({ user: { id: "user-1", groups: [new Map()] } })],
		[
			"a user whose email is a shared buffer",
			carrying({ user: { id: "user-1", email: new SharedArrayBuffer(8) } }),
		],
	])("answers nothing for %s", (_label, req) => {
		expect(cookieSessionUser(req as never, "user-1")).toBeUndefined();
	});

	it("answers the fields User declares alone, read by name: nothing else the session's user holds", () => {
		const held = {
			id: "user-1",
			email: "alice@example.com",
			joined: new Date(0),
			roles: new Map(),
			greet: () => "hi",
			passwordHash: "not-for-a-route",
		};
		expect(cookieSessionUser(carrying({ user: held }), "user-1")).toStrictEqual({
			id: "user-1",
			email: "alice@example.com",
		});
		const instance = new (class Account {
			id = "user-1";
			internals = { pool: "db" };
		})();
		expect(cookieSessionUser(carrying({ user: instance }), "user-1")).toStrictEqual({
			id: "user-1",
		});
		const hiddenId = Object.defineProperty({}, "id", { value: "user-1" });
		expect(cookieSessionUser(carrying({ user: hiddenId }), "user-1")).toStrictEqual({
			id: "user-1",
		});
	});

	it("round-trips the snapshot a login stored, as it is and through a session store's JSON", () => {
		const stored = passwordPrimary({
			subject: "user-1",
			user: {
				id: "user-1",
				username: "alice",
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				picture: "https://example.com/alice.png",
				groups: ["staff"],
				mfaEnrolled: true,
				locale: "en",
			},
			claims: {},
			authTime: new Date(0),
			redirectTo: undefined,
			request: {},
		}).user;
		expect(stored).not.toHaveProperty("locale");
		expect(cookieSessionUser(carrying({ user: stored }), "user-1")).toStrictEqual(stored);
		const throughJson = JSON.parse(JSON.stringify(stored));
		expect(cookieSessionUser(carrying({ user: throughJson }), "user-1")).toStrictEqual(stored);
	});

	it("never answers a user whose id is not the subject, even one whose id answers differently to each read", () => {
		let reads = 0;
		const user = {
			get id() {
				reads += 1;
				return reads === 1 ? "user-1" : "user-2";
			},
		};
		const answered = cookieSessionUser(carrying({ user }), "user-1");
		expect(answered === undefined || answered.id === "user-1").toBe(true);
	});

	it("refuses, as the claim builder does, a request that is not an object, and a subject that is not a non-empty string", () => {
		for (const bad of [undefined, null, "cookie", 7]) {
			expect(() => cookieSessionUser(bad as never, "user-1"), String(bad)).toThrow(RangeError);
		}
		for (const subject of [undefined, "", 7, null, ["user-1"]]) {
			expect(
				() => cookieSessionUser(carrying(), subject as never),
				JSON.stringify(subject),
			).toThrow(RangeError);
		}
	});
});

describe("what admitSession refuses before it reads anything (a caller's fault is a RangeError)", () => {
	it("refuses a claim that a builder did not make, however well it is shaped", async () => {
		const forged = {
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "cookie",
		} as unknown as SessionClaim;
		await expect(admitSession(deps(), request({ claim: forged }))).rejects.toThrow(RangeError);
		const copy = { ...cookie() } as SessionClaim;
		await expect(admitSession(deps(), request({ claim: copy }))).rejects.toThrow(RangeError);
	});

	it("refuses a resolver the planner or resolverForTests did not build", async () => {
		const forged = {
			get: () => undefined,
			entries: () => [][Symbol.iterator](),
		} as unknown as SessionRequirementResolver;
		await expect(admitSession(deps({ requirements: forged }), request())).rejects.toThrow(
			RangeError,
		);
		await expect(
			admitSession(deps({ requirements: undefined as never }), request()),
		).rejects.toThrow(RangeError);
	});

	it("is the one construction-time check a consumer factory built by hand runs: checkResolver names the factory for a resolver missing or forged, and answers the one it built", () => {
		const forged = { get: () => undefined, entries: () => [][Symbol.iterator]() };
		for (const missing of [undefined, null]) {
			expect(() => checkResolver(missing, "createThing"), String(missing)).toThrow(RangeError);
			expect(() => checkResolver(missing, "createThing"), String(missing)).toThrow(
				/^createThing: requirements is required — the sessionRequirementResolver the boot planner built/,
			);
		}
		expect(() => checkResolver(forged, "createThing")).toThrow(RangeError);
		expect(() => checkResolver(forged, "createThing")).toThrow(
			/^createThing: requirements must be the sessionRequirementResolver the boot planner built/,
		);
		const built = resolverForTests([], { actions: TEST_ACTIONS });
		expect(checkResolver(built, "createThing")).toBe(built);
	});

	it("checkResolver refuses, by the factory's name, a resolver on which an action the factory admits is not registered, and answers one on which every one is", () => {
		const built = resolverForTests([], { actions: TEST_ACTIONS });
		expect(checkResolver(built, "createThing", ["test.use", "test.peek"])).toBe(built);
		expect(() => checkResolver(built, "createThing", ["test.use", "acme.missing"])).toThrow(
			/^createThing: admits "acme\.missing", which no module registers/,
		);
		expect(() => checkResolver(resolverForTests([]), "createThing", ["test.use"])).toThrow(
			RangeError,
		);
	});

	it("refuses an action that is neither a registered action's name nor a remediation core issued — before a store is read or a requirement asked, never as a skipped requirement", async () => {
		let asked = 0;
		let read = 0;
		const record = session();
		const counting = met("counting", {
			admit: async () => {
				asked++;
				return { outcome: "met" };
			},
		});
		const store = holding(record);
		const with_ = deps({
			userSessionStore: {
				...store,
				get: async (sid) => {
					read++;
					return store.get(sid);
				},
			},
			requirements: resolverForTests([counting], { actions: TEST_ACTIONS }),
		});
		const registered = with_.requirements.action("test.use");
		for (const action of [
			undefined,
			null,
			"oauth.authorize",
			// A registered name with a grade the caller states, even the registered one.
			{ name: "test.use", grade: "grants_nothing" },
			{ name: "test.use", grade: "use" },
			{ name: "acme.x", grade: "use" },
			// The registered action as the resolver answers it, and a copy of it.
			registered,
			{ ...registered },
			{ name: "", grade: "use" },
			{ name: "x", grade: "strict" },
			{ name: "x", grade: "admin" },
			{ name: "x", grade: "" },
			{ name: "x", grade: undefined },
			{ name: "x" },
			{ name: 7, grade: "use" },
			{ grade: "use" },
		]) {
			await expect(
				admitSession(with_, request({ action: action as never })),
				JSON.stringify(action),
			).rejects.toThrow(RangeError);
		}
		expect(read).toBe(0);
		expect(asked).toBe(0);
	});

	it("refuses asks that are not a list of acr values, and a table that is not one", async () => {
		for (const acrValues of ["urn:x", [7], [""], null]) {
			await expect(
				admitSession(deps(), request({ asks: { acrValues: acrValues as never } })),
				JSON.stringify(acrValues),
			).rejects.toThrow(RangeError);
		}
		await expect(admitSession(deps({ acrTable: null as never }), request())).rejects.toThrow(
			RangeError,
		);
	});

	it("reads nothing when it refuses: the store is not asked", async () => {
		let asked = 0;
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		await expect(
			admitSession(deps({ userSessionStore: store }), request({ action: {} as never })),
		).rejects.toThrow(RangeError);
		expect(asked).toBe(0);
	});
});

describe("step 1 — the claim", () => {
	it("answers unauthenticated for a claim that is not authenticated, reading no store", async () => {
		let asked = 0;
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		expect(
			await admitSession(
				deps({ userSessionStore: store }),
				request({ claim: cookie({ isAuthenticated: false }) }),
			),
		).toEqual({ outcome: "unauthenticated" });
		expect(asked).toBe(0);
	});

	it("answers not_live (no_subject) for a cookie without a subject, logged at warn with the action and nothing else, not audited: the three consumers that refuse it keep doing so, and the two that did not join them", async () => {
		const { logger, lines } = recordingLogger();
		const { sink, events } = recordingSink();
		let read = 0;
		const store = holding(session());
		expect(
			await admitSession(
				deps({
					userSessionStore: {
						...store,
						get: async (sid) => {
							read++;
							return store.get(sid);
						},
					},
					logger,
					auditSink: sink,
				}),
				request({ claim: cookie({ user: undefined }) }),
			),
		).toEqual({ outcome: "not_live", reason: "no_subject" });
		expect(read).toBe(0);
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_no_subject",
				fields: { action: "test.use" },
			},
		]);
		expect(events).toEqual([]);
	});

	it("does not ask a subject of a code claim's first read, which has none", async () => {
		expect(
			await admitSession(deps(), request({ claim: codeClaimFirstRead({ sid: "sid-1" }) })),
		).toMatchObject({ outcome: "admitted" });
	});
});

describe("step 2 — the live read", () => {
	it("answers not_live (no_sid) with a store and no sid", async () => {
		expect(await admitSession(deps(), request({ claim: cookie({ sid: undefined }) }))).toEqual({
			outcome: "not_live",
			reason: "no_sid",
		});
	});

	it("skips the read for a token without a sid, as the refresh grant does today: the session is null and the requirements decide", async () => {
		let asked = 0;
		const seen: RequirementInput[] = [];
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(
				deps({
					userSessionStore: store,
					requirements: resolverForTests([watching], { actions: TEST_ACTIONS }),
				}),
				request({ claim: tokenClaim({ sub: "user-1", amr: ["pwd"] }) }),
			),
		).toEqual({ outcome: "admitted", session: null, view: null, acr: undefined });
		expect(asked).toBe(0);
		expect(seen[0]).toMatchObject({ session: null, carrier: "token" });
	});

	it("answers not_live (gone) for a record whose authTime is not a valid Date, as for one without a sub — never a throw from the view", async () => {
		for (const authTime of [undefined, "2026-09-29", new Date(Number.NaN), 0]) {
			expect(
				await admitSession(
					deps({ userSessionStore: holding(session({ authTime: authTime as never })) }),
					request(),
				),
				String(authTime),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
	});

	it("reads the record for a token with a sid, and compares its sub", async () => {
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1" }) })),
		).toMatchObject({ outcome: "admitted", session: session() });
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-1", sub: "user-2" }) })),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-9", sub: "user-1" }) })),
		).toEqual({ outcome: "not_live", reason: "gone" });
	});

	it("answers not_live (gone) for a store that answers null or undefined", async () => {
		for (const answer of [null, undefined]) {
			expect(
				await admitSession(deps({ userSessionStore: storeOf(async () => answer) }), request()),
				String(answer),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
	});

	it("answers not_live (gone) for a record whose sub is not a non-empty string", async () => {
		for (const sub of ["", undefined, 7]) {
			expect(
				await admitSession(
					deps({ userSessionStore: holding(session({ sub: sub as never })) }),
					request({ claim: codeClaimFirstRead({ sid: "sid-1" }) }),
				),
				String(sub),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
	});

	it("answers not_live (gone) for a record whose expiresAt is not later than now: the port does not promise that get filters expiry", async () => {
		for (const expiresAt of [NOW, minutesAgo(1), new Date(Number.NaN), undefined, "later"]) {
			expect(
				await admitSession(
					deps({ userSessionStore: holding(session({ expiresAt: expiresAt as never })) }),
					request(),
				),
				String(expiresAt),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
		expect(
			await admitSession(
				deps({ userSessionStore: holding(session({ expiresAt: new Date(NOW.getTime() + 1) })) }),
				request(),
			),
		).toMatchObject({ outcome: "admitted" });
	});

	it("answers unavailable (user_session) when the store throws, logged once at error with the store, the action and the projection — never the sid", async () => {
		const { logger, lines } = recordingLogger();
		const failure = Object.assign(new Error("ECONNRESET sid-1"), { command: { args: ["sid-1"] } });
		expect(
			await admitSession(
				deps({
					userSessionStore: storeOf(async () => {
						throw failure;
					}),
					logger,
				}),
				request(),
			),
		).toEqual({ outcome: "unavailable", store: "user_session" });
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "user_session", action: "test.use" },
		});
		expect(lines[0]?.fields.err).toMatchObject({ name: "Error" });
		expect(lines[0]?.fields.err).not.toBe(failure);
		expect(JSON.stringify(lines[0]?.fields)).not.toContain('"sid"');
		expect(JSON.stringify(lines[0]?.fields)).not.toContain("args");
	});

	it("answers unavailable (user_session) when reading the store off deps throws, logged once at error — never a rejection", async () => {
		const { logger, lines } = recordingLogger();
		const throwing = {
			...deps({ logger }),
			get userSessionStore(): UserSessionStore {
				throw new Error("deps down");
			},
		};
		expect(await admitSession(throwing, request())).toEqual({
			outcome: "unavailable",
			store: "user_session",
		});
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "user_session", action: "test.use" },
		});
	});

	it("reads no session without a store: the requirements decide what null means, and with none registered a cookie-only composition is admitted", async () => {
		const seen: RequirementInput[] = [];
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(
				deps({
					userSessionStore: undefined,
					requirements: resolverForTests([watching], { actions: TEST_ACTIONS }),
				}),
				request(),
			),
		).toEqual({ outcome: "admitted", session: null, view: null, acr: undefined });
		expect(seen).toHaveLength(1);
		expect(seen[0]).toMatchObject({ session: null, authentication: null });
	});

	it("answers the live record itself on admitted", async () => {
		const record = session();
		const admission = await admitSession(deps({ userSessionStore: holding(record) }), request());
		expect(admission).toEqual({
			outcome: "admitted",
			session: record,
			view: viewOf(record, false),
			acr: undefined,
		});
	});
});

describe("step 3 — the subject", () => {
	it("answers not_live (subject_mismatch) when the claim's subject is not the record's, logged once at warn with the action and no identifier, and audited with the sid and both subjects", async () => {
		const { logger, lines } = recordingLogger();
		const { sink, events } = recordingSink();
		expect(
			await admitSession(
				deps({ logger, auditSink: sink }),
				request({ claim: cookie({ user: { id: "user-2" } }) }),
			),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_subject_mismatch",
				fields: { action: "test.use" },
			},
		]);
		await flush();
		expect(events).toEqual([
			{
				timestamp: NOW,
				type: "session.admission.subject_mismatch",
				subject: "user-1",
				details: {
					sid: "sid-1",
					carrier: "cookie",
					claimedSubject: "user-2",
					recordSubject: "user-1",
				},
			},
		]);
	});

	it("compares a code claim's second read with the first read's subject", async () => {
		expect(
			await admitSession(
				deps(),
				request({ claim: codeClaimRevalidation({ sid: "sid-1" }, "user-2") }),
			),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(
			await admitSession(
				deps(),
				request({ claim: codeClaimRevalidation({ sid: "sid-1" }, "user-1") }),
			),
		).toMatchObject({ outcome: "admitted" });
	});

	it("logs and audits nothing when the subjects agree, and nothing without a logger or a sink", async () => {
		const { logger, lines } = recordingLogger();
		const { sink, events } = recordingSink();
		await admitSession(deps({ logger, auditSink: sink }), request());
		await flush();
		expect(lines).toEqual([]);
		expect(events).toEqual([]);
		// No logger, no sink: the refusal stands all the same.
		expect(
			await admitSession(deps(), request({ claim: cookie({ user: { id: "user-2" } }) })),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
	});

	it("reads deps.auditSink only to audit a mismatch: a getter that throws fails as a sink that throws — the answer stands, never a rejection", async () => {
		let reads = 0;
		const { logger, lines } = recordingLogger();
		const throwing = {
			...deps({ logger }),
			get auditSink(): AuditSink {
				reads++;
				throw new Error("sink unreadable");
			},
		};
		expect(await admitSession(throwing, request())).toMatchObject({ outcome: "admitted" });
		expect(reads).toBe(0);
		expect(
			await admitSession(throwing, request({ claim: cookie({ user: { id: "user-2" } }) })),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(reads).toBe(1);
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_subject_mismatch",
				fields: { action: "test.use" },
			},
		]);
	});
});

describe("step 4 — the revocation boundary", () => {
	it("answers revoked for a session established at or before the subject's boundary, within the skew", async () => {
		const record = session({ authTime: minutesAgo(5) });
		for (const boundary of [
			minutesAgo(5),
			minutesAgo(1),
			new Date(minutesAgo(5).getTime() - 999),
		]) {
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						subjectRevocation: revocationOf(async () => boundary),
					}),
					request(),
				),
				boundary.toISOString(),
			).toEqual({ outcome: "revoked" });
		}
	});

	it("reads the boundary for a code claim — either read — and a link claim as for a cookie: only a token carrier's is verifyJwt's", async () => {
		const record = session({ authTime: minutesAgo(5) });
		for (const [label, claim] of [
			["a code's first read", codeClaimFirstRead({ sid: "sid-1" })],
			["a code's revalidation", codeClaimRevalidation({ sid: "sid-1" }, "user-1")],
			["a link", linkClaim({ sid: "sid-1", subject: "user-1" })],
		] as const) {
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						subjectRevocation: revocationOf(async () => minutesAgo(1)),
					}),
					request({ claim }),
				),
				label,
			).toEqual({ outcome: "revoked" });
		}
	});

	it("admits a session established after the boundary, or with no boundary in force", async () => {
		const record = session({ authTime: minutesAgo(5) });
		for (const boundary of [null, minutesAgo(6)]) {
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						subjectRevocation: revocationOf(async () => boundary),
					}),
					request(),
				),
				String(boundary),
			).toMatchObject({ outcome: "admitted" });
		}
	});

	it("reads the boundary for the record's subject", async () => {
		const asked: string[] = [];
		await admitSession(
			deps({
				subjectRevocation: revocationOf(async (subject) => {
					asked.push(subject);
					return null;
				}),
			}),
			request(),
		);
		expect(asked).toEqual(["user-1"]);
	});

	it("answers unavailable (revocation_boundary) for a throw, or an answer that is neither null nor a valid date, logged once", async () => {
		const { logger, lines } = recordingLogger();
		for (const answer of [
			async () => {
				throw new Error("down");
			},
			async () => "2026-01-01",
			async () => new Date(Number.NaN),
			async () => undefined,
			async () => 0,
		]) {
			lines.length = 0;
			expect(
				await admitSession(
					deps({ subjectRevocation: revocationOf(answer), logger }),
					request({ action: "test.peek" }),
				),
			).toEqual({ outcome: "unavailable", store: "revocation_boundary" });
			expect(lines).toHaveLength(1);
			expect(lines[0]).toMatchObject({
				level: "error",
				message: "session_admission_unavailable",
				fields: { store: "revocation_boundary", action: "test.peek" },
			});
		}
	});

	it("answers unavailable (revocation_boundary) when reading the boundary off deps throws, logged once at error — never a rejection", async () => {
		const { logger, lines } = recordingLogger();
		const throwing = {
			...deps({ logger }),
			get subjectRevocation(): SubjectRevocation {
				throw new Error("deps down");
			},
		};
		expect(await admitSession(throwing, request())).toEqual({
			outcome: "unavailable",
			store: "revocation_boundary",
		});
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "revocation_boundary", action: "test.use" },
		});
	});

	it("does not read the boundary for a token carrier: verifyJwt reads it, so the two readings do not double up", async () => {
		let asked = 0;
		expect(
			await admitSession(
				deps({
					subjectRevocation: revocationOf(async () => {
						asked++;
						return minutesAgo(1);
					}),
				}),
				request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1" }) }),
			),
		).toMatchObject({ outcome: "admitted" });
		expect(asked).toBe(0);
	});

	it("does not read the boundary without a store: no record, no authTime and no sub to compare", async () => {
		let asked = 0;
		expect(
			await admitSession(
				deps({
					userSessionStore: undefined,
					subjectRevocation: revocationOf(async () => {
						asked++;
						return minutesAgo(1);
					}),
				}),
				request(),
			),
		).toMatchObject({ outcome: "admitted", session: null });
		expect(asked).toBe(0);
	});

	it("reads the boundary before any requirement is asked", async () => {
		let asked = 0;
		const watching = met("watch", {
			admit: async () => {
				asked++;
				return { outcome: "met" };
			},
		});
		await admitSession(
			deps({
				subjectRevocation: revocationOf(async () => minutesAgo(1)),
				requirements: resolverForTests([watching], { actions: TEST_ACTIONS }),
			}),
			request(),
		);
		expect(asked).toBe(0);
	});
});

describe("step 5 — the requirements", () => {
	it("hands each requirement a view of the session — sid, sub, authTime, expiresAt, whether a second factor can be recorded — never the record, with the vouched authentication, the action, the asks and now", async () => {
		const asked = { acrValues: ["urn:x"] };
		const seen: RequirementInput[] = [];
		const record = session({ amr: ["hwk", "fed"], authentication: undefined });
		await admitSession(
			deps({
				userSessionStore: holding(record),
				requirements: resolverForTests(
					[
						met("watch", {
							admit: async (input) => {
								seen.push(input);
								return { outcome: "met" };
							},
						}),
					],
					{ actions: TEST_ACTIONS },
				),
			}),
			request({ asks: asked }),
		);
		expect(seen).toHaveLength(1);
		const input = seen[0] as RequirementInput;
		expect(input.session).toEqual({
			sid: "sid-1",
			sub: "user-1",
			authTime: record.authTime,
			expiresAt: record.expiresAt,
			// `holding` has no `recordSecondFactor`.
			secondFactorRecordable: false,
		});
		expect(input.session).not.toBe(record);
		expect(Object.keys(input.session ?? {})).toEqual([
			"sid",
			"sub",
			"authTime",
			"expiresAt",
			"secondFactorRecordable",
		]);
		// The vouched amr, split as the MFA ADR's D9 reads a pre-upgrade record:
		// `hwk` is an untrusted IdP's word.
		expect(input.authentication).toEqual({
			authentication: {
				primary: "fed",
				federation: undefined,
				upstreamAmr: ["hwk"],
				mfaAt: undefined,
			},
			amr: ["fed"],
		});
		expect(input.carrier).toBe("cookie");
		expect(input.subject).toBe("user-1");
		expect(input.action).toEqual({ name: "test.use", grade: "use" });
		expect(input.asks).toEqual({ acrValues: ["urn:x"] });
		// The asks are core's copy, frozen: a requirement cannot drop the acr
		// request for the ones asked after it, nor reach the caller's object.
		expect(Object.isFrozen(input.asks)).toBe(true);
		expect(Object.isFrozen(input.asks?.acrValues)).toBe(true);
		expect(input.asks).not.toBe(asked);
		expect(input.asks?.acrValues).not.toBe(asked.acrValues);
		expect(input.now).toEqual(NOW);
	});

	it("builds a token carrier's authentication from the token's amr when no record was read: the primary from fed or pwd, else unknown, no mfaAt, the amr as vouched", async () => {
		const seen: RequirementInput[] = [];
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		const without = deps({
			userSessionStore: undefined,
			requirements: resolverForTests([watching], { actions: TEST_ACTIONS }),
		});
		for (const amr of [["pwd", "otp", "mfa"], ["hwk", "fed"], ["otp"], undefined]) {
			await admitSession(without, request({ claim: tokenClaim({ sub: "user-1", amr }) }));
		}
		expect(seen.map((input) => input.authentication)).toEqual([
			{
				authentication: {
					primary: "pwd",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
				amr: ["pwd", "otp", "mfa"],
			},
			{
				authentication: {
					primary: "fed",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
				amr: ["hwk", "fed"],
			},
			{ authentication: undefined, amr: ["otp"] },
			{ authentication: undefined, amr: [] },
		]);
		// With a record, the token's own amr is still what the requirements are
		// asked about; the record is only the view.
		await admitSession(
			deps({ requirements: resolverForTests([watching], { actions: TEST_ACTIONS }) }),
			request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["hwk", "fed"] }) }),
		);
		expect(seen.at(-1)?.authentication).toEqual({
			authentication: {
				primary: "fed",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
			amr: ["hwk", "fed"],
		});
		expect(seen.at(-1)?.session).toMatchObject({ sid: "sid-1", sub: "user-1" });
	});

	it("asks every requirement for use and credential_change, in registration order", async () => {
		const asked: string[] = [];
		const watching = (name: string) =>
			met(name, {
				admit: async () => {
					asked.push(name);
					return { outcome: "met" };
				},
			});
		const requirements = resolverForTests([watching("b"), watching("a")], {
			actions: TEST_ACTIONS,
		});
		await admitSession(deps({ requirements }), request());
		await admitSession(deps({ requirements }), request({ action: "test.change" }));
		expect(asked).toEqual(["b", "a", "b", "a"]);
	});

	it("asks no requirement for the remediation action core issued to the requirement that declared it: the route belongs to the requirement", async () => {
		let asked = 0;
		const owner = met("mfa", {
			remediations: ["mfa.step_up"],
			admit: async () => {
				asked++;
				return { outcome: "unmet" };
			},
		});
		const requirements = resolverForTests([owner, met("other")], { actions: TEST_ACTIONS });
		const issued = issuedRemediationActions(owner)?.step_up;
		expect(issued).toEqual({ name: "mfa.step_up", grade: "remediation" });
		expect(
			await admitSession(
				deps({ requirements }),
				request({ action: issued as IssuedRemediationAction }),
			),
		).toMatchObject({ outcome: "admitted" });
		expect(asked).toBe(0);
	});

	it("keeps the remediation grade for the issued object itself, and refuses a literal or a copy of it", async () => {
		const seen: string[] = [];
		const owner = met("mfa", {
			remediations: ["mfa.step_up"],
			admit: async ({ action }) => {
				seen.push(`mfa:${action.name}:${action.grade}`);
				return { outcome: "met" };
			},
		});
		const other = met("other", {
			admit: async ({ action }) => {
				seen.push(`other:${action.name}:${action.grade}`);
				return { outcome: "met" };
			},
		});
		const requirements = resolverForTests([owner, other], { actions: TEST_ACTIONS });
		const issued = issuedRemediationActions(owner)?.step_up as IssuedRemediationAction;
		for (const action of [
			{ name: "mfa.step_up", grade: "remediation" } as const,
			{ ...issued },
			Object.freeze({ ...issued }),
		]) {
			await expect(
				admitSession(deps({ requirements }), request({ action: action as never })),
				JSON.stringify(action),
			).rejects.toThrow(RangeError);
		}
		// The issued object itself: the route's own, no requirement asked.
		expect(await admitSession(deps({ requirements }), request({ action: issued }))).toMatchObject({
			outcome: "admitted",
		});
		expect(seen).toEqual([]);
	});

	it("asks every requirement, as credential_change, about a remediation core issued to a requirement it does not hold, said once per process per name", async () => {
		const { logger, lines } = recordingLogger();
		const seen: string[] = [];
		const watching = (name: string) =>
			met(name, {
				admit: async ({ action }) => {
					seen.push(`${name}:${action.name}:${action.grade}`);
					return { outcome: "met" };
				},
			});
		// Registered elsewhere — another composition's — so issued, but not to these.
		const elsewhere = met("elsewhere", { remediations: ["elsewhere.step_up"] });
		resolverForTests([elsewhere], { actions: TEST_ACTIONS });
		const undeclared = issuedRemediationActions(elsewhere)?.step_up as IssuedRemediationAction;
		const first = deps({
			requirements: resolverForTests([watching("one"), watching("two")], { actions: TEST_ACTIONS }),
			logger,
		});
		await admitSession(first, request({ action: undeclared }));
		await admitSession(first, request({ action: undeclared }));
		expect(seen).toEqual([
			"one:elsewhere.step_up:credential_change",
			"two:elsewhere.step_up:credential_change",
			"one:elsewhere.step_up:credential_change",
			"two:elsewhere.step_up:credential_change",
		]);
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_remediation_undeclared",
				fields: { action: "elsewhere.step_up" },
			},
		]);
	});

	it("answers unavailable (the requirement's name) when a requirement throws, logged once: a requirement is never trusted to fail open", async () => {
		const { logger, lines } = recordingLogger();
		const failing = met("risk", {
			admit: async () => {
				throw new Error("scorer down");
			},
		});
		expect(
			await admitSession(
				deps({
					requirements: resolverForTests([failing, met("after")], { actions: TEST_ACTIONS }),
					logger,
				}),
				request({ action: "test.use" }),
			),
		).toEqual({ outcome: "unavailable", store: "risk" });
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "risk", action: "test.use" },
		});
	});

	it("answers unavailable (the requirement's name) for a verdict that is not one of the four", async () => {
		const { logger, lines } = recordingLogger();
		for (const verdict of [
			undefined,
			"met",
			{ outcome: "maybe" },
			{ outcome: "step_up" },
			{ outcome: "step_up", whenStillUnmet: "retry" },
		]) {
			lines.length = 0;
			const odd = met("odd", { admit: async () => verdict as never });
			expect(
				await admitSession(
					deps({ requirements: resolverForTests([odd], { actions: TEST_ACTIONS }), logger }),
					request(),
				),
				JSON.stringify(verdict),
			).toEqual({ outcome: "unavailable", store: "odd" });
			expect(lines).toHaveLength(1);
		}
	});

	it("answers the requirement's registered page on step_up, never one the verdict names: a getter is read once at registration", async () => {
		let reads = 0;
		const record = session();
		const requirement = {
			name: "r",
			reach: new Set(["risk-ok"]),
			get stepUpPage() {
				reads++;
				return { url: "/r", params: { v: String(reads) } };
			},
			remediations: [],
			hintKeys: [],
			admit: async () =>
				({
					outcome: "step_up",
					whenStillUnmet: "unmet",
					page: { url: "/evil", params: {} },
				}) as never,
		} satisfies SessionRequirement;
		const requirements = anyReach([requirement]);
		expect(reads).toBe(1);
		expect(
			await admitSession(deps({ userSessionStore: holding(record), requirements }), request()),
		).toEqual({
			outcome: "step_up",
			requirement: "r",
			session: record,
			view: viewOf(record, false),
			// As registered: resolved once, on the issuer, to the URL a
			// consumer answers.
			page: { url: "/r", params: { v: "1" }, href: `${ISSUER}/r?v=1` },
			acrValues: [],
			whenStillUnmet: "unmet",
		});
		expect(reads).toBe(1);
	});

	it("takes a step_up from a requirement that registered no page as unmet by its name, said once per process: nothing could finish the trip", async () => {
		const { logger, lines } = recordingLogger();
		const record = session();
		const pageless = met("pageless", {
			admit: async () => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }),
		});
		const with_ = deps({
			userSessionStore: holding(record),
			requirements: resolverForTests([pageless], { actions: TEST_ACTIONS }),
			logger,
		});
		expect(await admitSession(with_, request())).toEqual({
			outcome: "unmet",
			requirement: "pageless",
			session: record,
		});
		expect(await admitSession(with_, request())).toMatchObject({ outcome: "unmet" });
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_step_up_without_page",
				fields: { requirement: "pageless" },
			},
		]);
	});

	it("takes a step_up over no session as reauthenticate by the requirement's name, said once per process: step_up always carries a live session", async () => {
		const { logger, lines } = recordingLogger();
		const stepping = met("stepping", {
			reach: new Set(["risk-ok"]),
			stepUpPage: { url: "/stepping", params: {} },
			admit: async () => ({ outcome: "step_up", whenStillUnmet: "unmet" }),
		});
		const without = deps({
			userSessionStore: undefined,
			requirements: anyReach([stepping]),
			logger,
		});
		expect(await admitSession(without, request())).toEqual({
			outcome: "reauthenticate",
			requirement: "stepping",
			session: null,
		});
		expect(
			await admitSession(without, request({ claim: tokenClaim({ sub: "user-1", amr: ["pwd"] }) })),
		).toMatchObject({ outcome: "reauthenticate", session: null });
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_step_up_without_session",
				fields: { requirement: "stepping" },
			},
		]);
	});

	it("reads the reach the resolver sealed, not the contributor's: a reach that fills after the resolver was built does not count until one is built over it again", async () => {
		const record = session();
		const reach = new Set<string>();
		const late: SessionRequirement = {
			name: "late",
			get reach() {
				return reach;
			},
			stepUpPage: { url: "/late", params: {} },
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
		};
		const acrTable = readAcrTable({ "urn:o3co:acr:mfa": ["mfa"] });
		const ask = (requirements: SessionRequirementResolver) =>
			admitSession(
				deps({ userSessionStore: holding(record), requirements, acrTable }),
				request({ asks: { acrValues: ["urn:o3co:acr:mfa"] } }),
			);
		const sealedEmpty = anyReach([late]);
		expect(await ask(sealedEmpty)).toMatchObject({ outcome: "unmet", requirement: "acr" });
		reach.add("mfa");
		expect(await ask(sealedEmpty)).toMatchObject({ outcome: "unmet", requirement: "acr" });
		expect(await ask(anyReach([late]))).toMatchObject({
			outcome: "step_up",
			requirement: "late",
		});
	});

	it("answers a step_up from a requirement that reaches nothing but registered a page — a re-consent — with that page", async () => {
		const record = session();
		const consent = met("consent", {
			stepUpPage: { url: "/consent", params: { reason: "terms" } },
			admit: async () => ({ outcome: "step_up", whenStillUnmet: "unmet" }),
		});
		expect(
			await admitSession(
				deps({
					userSessionStore: holding(record),
					requirements: resolverForTests([consent], { issuer: ISSUER, actions: TEST_ACTIONS }),
				}),
				request(),
			),
		).toMatchObject({
			outcome: "step_up",
			requirement: "consent",
			page: {
				url: "/consent",
				params: { reason: "terms" },
				href: `${ISSUER}/consent?reason=terms`,
			},
			session: record,
		});
	});

	it("carries the live session on reauthenticate, step_up and unmet: /authorize decides freshness on it first", async () => {
		const record = session();
		for (const verdict of [
			{ outcome: "reauthenticate" as const },
			{ outcome: "unmet" as const },
			{ outcome: "step_up" as const, whenStillUnmet: "reauthenticate" as const },
		]) {
			const requirement = met("r", {
				reach: new Set(["risk-ok"]),
				stepUpPage: { url: "/r", params: {} },
				admit: async () => verdict,
			});
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						requirements: anyReach([requirement]),
					}),
					request(),
				),
				verdict.outcome,
			).toMatchObject({ outcome: verdict.outcome, requirement: "r", session: record });
		}
	});
});

describe("step 5 — what a requirement answers is validated at the boundary", () => {
	it("answers unavailable, logged once at error, for anything that is not a verdict: null, a string, an unknown outcome, a step_up without whenStillUnmet — exactly as a throw", async () => {
		const record = session();
		for (const garbage of [
			null,
			undefined,
			"met",
			7,
			{},
			[],
			{ outcome: "admin" },
			{ outcome: "step_up" },
			{ outcome: "step_up", whenStillUnmet: "later" },
		]) {
			const { logger, lines } = recordingLogger();
			let askedOther = 0;
			const odd = met("odd", { admit: async () => garbage as never });
			const other = met("other", {
				admit: async () => {
					askedOther++;
					return { outcome: "met" };
				},
			});
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						requirements: resolverForTests([odd, other], { actions: TEST_ACTIONS }),
						logger,
					}),
					request(),
				),
				JSON.stringify(garbage),
			).toEqual({ outcome: "unavailable", store: "odd" });
			expect(askedOther, JSON.stringify(garbage)).toBe(0);
			expect(lines, JSON.stringify(garbage)).toHaveLength(1);
			expect(lines[0]).toMatchObject({
				level: "error",
				message: "session_admission_unavailable",
				fields: { store: "odd", action: "test.use" },
			});
		}
	});

	it("answers unavailable (the requirement's name), logged once at error, for an answer whose outcome or whenStillUnmet getter throws — never a rejection", async () => {
		const throwing = (field: "outcome" | "whenStillUnmet") =>
			field === "outcome"
				? {
						get outcome(): string {
							throw new Error("outcome unreadable");
						},
					}
				: {
						outcome: "step_up",
						get whenStillUnmet(): string {
							throw new Error("whenStillUnmet unreadable");
						},
					};
		for (const field of ["outcome", "whenStillUnmet"] as const) {
			const { logger, lines } = recordingLogger();
			let askedOther = 0;
			const odd = met("odd", { admit: async () => throwing(field) as never });
			const other = met("other", {
				admit: async () => {
					askedOther++;
					return { outcome: "met" };
				},
			});
			expect(
				await admitSession(
					deps({
						requirements: resolverForTests([odd, other], { actions: TEST_ACTIONS }),
						logger,
					}),
					request(),
				),
				field,
			).toEqual({ outcome: "unavailable", store: "odd" });
			expect(askedOther, field).toBe(0);
			expect(lines, field).toHaveLength(1);
			expect(lines[0], field).toMatchObject({
				level: "error",
				message: "session_admission_unavailable",
				fields: { store: "odd", action: "test.use" },
			});
		}
	});

	it("hands the requirement the subject: the record's sub when one was read, else the claim's — undefined only on the code record's first read", async () => {
		const seen: (string | undefined)[] = [];
		const watching = met("watch", {
			admit: async ({ subject }) => {
				seen.push(subject);
				return { outcome: "met" };
			},
		});
		const record = session();
		const cases: [string, AdmissionDeps, SessionClaim][] = [
			["a cookie with a record", deps({ userSessionStore: holding(record) }), cookie()],
			["a cookie without a store", deps({ userSessionStore: undefined }), cookie()],
			[
				"a code's first read with a record",
				deps({ userSessionStore: holding(record) }),
				codeClaimFirstRead({ sid: "sid-1" }),
			],
			[
				"a code's first read without a store",
				deps({ userSessionStore: undefined }),
				codeClaimFirstRead({ sid: "sid-1" }),
			],
			[
				"a code's revalidation without a store",
				deps({ userSessionStore: undefined }),
				codeClaimRevalidation({ sid: "sid-1" }, "user-1"),
			],
			[
				"a token without a sid, the store not read",
				deps(),
				tokenClaim({ sub: "user-1", amr: ["pwd"] }),
			],
		];
		const subjects: (string | undefined)[] = [];
		for (const [label, with_, claim] of cases) {
			seen.length = 0;
			await admitSession(
				{ ...with_, requirements: resolverForTests([watching], { actions: TEST_ACTIONS }) },
				request({ claim }),
			);
			expect(seen, label).toHaveLength(1);
			subjects.push(seen[0]);
		}
		expect(subjects).toEqual(["user-1", "user-1", "user-1", undefined, "user-1", "user-1"]);
	});
});

describe("every untrusted input is read once, into a copy — a getter or a swap after the check changes nothing", () => {
	it("a claim: the request's claim is read once, so a getter cannot answer a branded claim to the check and a forged one to the steps", async () => {
		let reads = 0;
		const branded = cookieClaim({ session: { isAuthenticated: false } });
		const forged = { authenticated: true, sid: "sid-1", subject: "user-1", carrier: "cookie" };
		const request = {
			get claim() {
				reads++;
				return reads <= 2 ? branded : forged;
			},
			action: "test.use",
		};
		expect(await admitSession(deps(), request as never)).toEqual({ outcome: "unauthenticated" });
	});

	it("the resolver: deps.requirements is read once, so a getter cannot answer the planner's to the check and a home-made one to the steps", async () => {
		let reads = 0;
		const real = resolverForTests(
			[met("hold", { admit: async () => ({ outcome: "reauthenticate" }) })],
			{ actions: TEST_ACTIONS },
		);
		const fake = { get: () => undefined, entries: () => new Map().entries() };
		const with_ = {
			...deps(),
			get requirements() {
				reads++;
				return reads === 1 ? real : fake;
			},
		};
		expect(await admitSession(with_ as never, request())).toMatchObject({
			outcome: "reauthenticate",
			requirement: "hold",
		});
	});

	it("the action: read once, so a name that changes between reads reaches the requirements as it was checked", async () => {
		let reads = 0;
		let seen: string | undefined;
		const watching = met("watch", {
			admit: async ({ action }) => {
				seen = action.grade;
				return { outcome: "met" };
			},
		});
		const asked = {
			claim: cookie(),
			get action() {
				reads++;
				return reads === 1 ? "test.use" : "test.peek";
			},
		};
		await admitSession(
			deps({ requirements: resolverForTests([watching], { actions: TEST_ACTIONS }) }),
			asked as never,
		);
		expect(seen).toBe("use");
	});

	it("the stores: deps.userSessionStore and deps.subjectRevocation are read once each, the record, the boundary and the step-up capability all off that one read", async () => {
		let storeReads = 0;
		let revocationReads = 0;
		let boundaryAsked = 0;
		let seen: RequirementInput | undefined;
		const store = Object.assign(holding(session()), { recordSecondFactor: async () => null });
		const revocation = revocationOf(async () => {
			boundaryAsked++;
			return null;
		});
		const watching = met("watch", {
			admit: async (input) => {
				seen = input;
				return { outcome: "met" };
			},
		});
		const counting = {
			...deps({ requirements: resolverForTests([watching], { actions: TEST_ACTIONS }) }),
			get userSessionStore(): UserSessionStore {
				storeReads++;
				return store;
			},
			get subjectRevocation(): SubjectRevocation {
				revocationReads++;
				return revocation;
			},
		};
		expect(await admitSession(counting, request())).toMatchObject({ outcome: "admitted" });
		expect(boundaryAsked).toBe(1);
		expect(seen?.session?.secondFactorRecordable).toBe(true);
		expect(storeReads).toBe(1);
		expect(revocationReads).toBe(1);
	});

	it("a verdict: outcome and whenStillUnmet are copied before they are checked, so a getter cannot pass the check as unmet and read as met", async () => {
		let reads = 0;
		let secondAsked = false;
		const tricky = met("a", {
			admit: async () =>
				({
					get outcome() {
						reads++;
						return reads <= 5 ? "unmet" : "met";
					},
				}) as never,
		});
		const strict = met("b", {
			admit: async () => {
				secondAsked = true;
				return { outcome: "reauthenticate" };
			},
		});
		expect(
			await admitSession(
				deps({ requirements: resolverForTests([tricky, strict], { actions: TEST_ACTIONS }) }),
				request(),
			),
		).toMatchObject({ outcome: "unmet", requirement: "a" });
		expect(secondAsked).toBe(false);
		let garbage = 0;
		const turning = met("c", {
			admit: async () =>
				({
					get outcome() {
						garbage++;
						return garbage <= 5 ? "unmet" : "garbage";
					},
				}) as never,
		});
		expect(
			await admitSession(
				deps({ requirements: resolverForTests([turning], { actions: TEST_ACTIONS }) }),
				request(),
			),
		).toMatchObject({ outcome: "unmet", requirement: "c" });
	});
});

describe("an action a consumer registered, passed by its name", () => {
	const ACTIONS = {
		"acme.export": { grade: "credential_change" },
		"acme.peek": { grade: "grants_nothing" },
	} as const;

	it("asks every requirement with the grade the action registered", async () => {
		const seen: AdmissionAction[] = [];
		const watching = met("probe", {
			admit: async ({ action }) => {
				seen.push(action);
				return { outcome: "met" };
			},
		});
		const requirements = resolverForTests([watching], { actions: ACTIONS });
		expect(
			await admitSession(deps({ requirements }), request({ action: "acme.export" })),
		).toMatchObject({ outcome: "admitted" });
		await admitSession(deps({ requirements }), request({ action: "acme.peek" }));
		expect(seen).toEqual([
			{ name: "acme.export", grade: "credential_change" },
			{ name: "acme.peek", grade: "grants_nothing" },
		]);
	});

	it("refuses a name nothing registers, naming it, before anything is read", async () => {
		let reads = 0;
		const store = storeOf(async () => {
			reads++;
			return session();
		});
		for (const requirements of [
			resolverForTests([], { actions: TEST_ACTIONS }),
			resolverForTests([], { actions: ACTIONS }),
		]) {
			await expect(
				admitSession(
					deps({ userSessionStore: store, requirements }),
					request({ action: "acme.import" }),
				),
			).rejects.toThrow(/"acme\.import" is not a registered admission action/);
		}
		expect(reads).toBe(0);
	});

	it("refuses an action object that is not a remediation core issued — a literal, a copy of a registered action, one shaped like a remediation — before anything is read", async () => {
		let reads = 0;
		const store = storeOf(async () => {
			reads++;
			return session();
		});
		const requirements = resolverForTests([], { actions: ACTIONS });
		const registered = requirements.action("acme.export");
		for (const action of [
			{ name: "acme.export", grade: "credential_change" },
			{ ...registered },
			registered,
			{ name: "acme.unregistered", grade: "use" },
			{ name: "acme.step_up", grade: "remediation" },
		]) {
			await expect(
				admitSession(
					deps({ userSessionStore: store, requirements }),
					request({ action: action as never }),
				),
				JSON.stringify(action),
			).rejects.toThrow(/a registered action's name, or a remediation core issued/);
		}
		expect(reads).toBe(0);
	});

	it("logs the action by its name: a registered action's, or an issued remediation's", async () => {
		const { logger, lines } = recordingLogger();
		const down = storeOf(async () => {
			throw new Error("down");
		});
		const owner = met("mfa", { remediations: ["mfa.step_up"] });
		const requirements = resolverForTests([owner], { actions: ACTIONS });
		await admitSession(
			deps({ userSessionStore: down, logger, requirements }),
			request({ action: "acme.peek" }),
		);
		await admitSession(
			deps({ userSessionStore: down, logger, requirements }),
			request({ action: issuedRemediationActions(owner)?.step_up as IssuedRemediationAction }),
		);
		expect(lines.map((line) => line.fields.action)).toEqual(["acme.peek", "mfa.step_up"]);
	});
});

describe("the undeclared-remediation line is capped", () => {
	it("says each name once up to 256 names, then once for all", async () => {
		const { logger, lines } = recordingLogger();
		const with_ = deps({ logger });
		for (let i = 0; i < 300; i++) {
			// Issued to a requirement registered elsewhere, not to this resolver's.
			const elsewhere = met(`route${i}`, { remediations: [`route${i}.step_up`] });
			resolverForTests([elsewhere], { actions: TEST_ACTIONS });
			await admitSession(
				with_,
				request({
					action: issuedRemediationActions(elsewhere)?.step_up as IssuedRemediationAction,
				}),
			);
		}
		expect(lines.length).toBeLessThanOrEqual(257);
		expect(lines.every((line) => typeof line.fields.action === "string")).toBe(true);
		expect(lines.filter((line) => line.fields.overflow === true)).toHaveLength(1);
		expect(lines[lines.length - 1]?.fields.overflow).toBe(true);
	});
});

describe("step 6 — acr_values, with the reach of what is registered", () => {
	const table = readAcrTable({ "urn:o3co:acr:mfa": ["mfa"], "urn:example:pwd": ["pwd"] });

	it("judges a token carrier on the token's own amr, never the record's: a sid-less token meets an acr from its amr", async () => {
		expect(
			await admitSession(
				deps({ acrTable: table }),
				request({
					claim: tokenClaim({ sub: "user-1", amr: ["pwd", "otp", "mfa"] }),
					asks: { acrValues: ["urn:o3co:acr:mfa"] },
				}),
			),
		).toEqual({ outcome: "admitted", session: null, view: null, acr: "urn:o3co:acr:mfa" });
	});

	it("judges a token with a sid on its own amr when the record's differs, in both directions", async () => {
		const stepped = session({
			amr: ["pwd", "otp", "mfa"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: minutesAgo(1),
			},
		});
		const ask = (record: UserSession, amr: readonly string[]) =>
			admitSession(
				deps({ userSessionStore: holding(record), acrTable: table }),
				request({
					claim: tokenClaim({ sid: "sid-1", sub: "user-1", amr }),
					asks: { acrValues: ["urn:o3co:acr:mfa"] },
				}),
			);
		// The record stepped up after the token was issued: the token is not.
		expect(await ask(stepped, ["pwd"])).toEqual({
			outcome: "unmet",
			requirement: "acr",
			session: stepped,
		});
		// The token carries mfa its record does not: the token's word counts.
		const plain = session();
		expect(await ask(plain, ["pwd", "otp", "mfa"])).toEqual({
			outcome: "admitted",
			session: plain,
			view: viewOf(plain, false),
			acr: "urn:o3co:acr:mfa",
		});
	});

	it("holds the token's amr in the merge too: a step-up is offered by what the token holds beside the requirement's reach", async () => {
		const both = readAcrTable({ "urn:example:both": ["kba", "hwk"] });
		const record = session();
		const requirements = resolverForTests(
			[
				met("verifier", {
					secondFactorAuthority: true,
					reach: new Set(["hwk"]),
					stepUpPage: { url: "/verifier", params: {} },
					remediations: ["verifier.step_up"],
				}),
			],
			{ issuer: ISSUER, actions: TEST_ACTIONS },
		);
		expect(
			await admitSession(
				deps({
					// A store that records a step-up: the authority's trip is offered.
					userSessionStore: Object.assign(holding(record), {
						recordSecondFactor: async () => null,
					}),
					acrTable: both,
					requirements,
				}),
				request({
					claim: tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["pwd", "kba"] }),
					asks: { acrValues: ["urn:example:both"] },
				}),
			),
		).toMatchObject({
			outcome: "step_up",
			requirement: "verifier",
			acrValues: ["urn:example:both"],
		});
	});

	it("selects over the vouched amr, with reach the union of every requirement's reach when the session is live", async () => {
		const requirements = anyReach([
			met("a", { reach: new Set(["risk-ok"]), stepUpPage: { url: "/a", params: {} } }),
			met("b", { reach: new Set(["mfa"]), stepUpPage: { url: "/b", params: {} } }),
		]);
		expect(
			await admitSession(
				deps({ acrTable: table, requirements }),
				request({ asks: { acrValues: ["urn:o3co:acr:mfa"] } }),
			),
		).toMatchObject({ outcome: "step_up", requirement: "b", acrValues: ["urn:o3co:acr:mfa"] });
		expect(
			await admitSession(
				deps({ acrTable: table, requirements }),
				request({ asks: { acrValues: ["urn:example:pwd"] } }),
			),
		).toMatchObject({ outcome: "admitted", acr: "urn:example:pwd" });
	});

	it("reaches nothing without a session: nothing can be stepped up onto no session", async () => {
		const requirements = anyReach([
			met("b", { reach: new Set(["mfa"]), stepUpPage: { url: "/b", params: {} } }),
		]);
		expect(
			await admitSession(
				deps({ acrTable: table, requirements, userSessionStore: undefined }),
				request({ asks: { acrValues: ["urn:o3co:acr:mfa"] } }),
			),
		).toEqual({ outcome: "unmet", requirement: "acr", session: null });
	});

	it("asks nothing of the table when no acr is asked for, and answers no acr", async () => {
		for (const asks of [undefined, {}, { acrValues: [] }]) {
			expect(
				await admitSession(deps({ acrTable: table }), request({ asks })),
				JSON.stringify(asks),
			).toEqual({
				outcome: "admitted",
				session: session(),
				view: viewOf(session(), false),
				acr: undefined,
			});
		}
	});
});

describe("the clock", () => {
	it("defaults to the wall clock: a record that expires in the future is live", async () => {
		const record = session({ expiresAt: new Date(Date.now() + 60_000) });
		const { now: _seam, ...withoutClock } = deps({ userSessionStore: holding(record) });
		expect(await admitSession(withoutClock, request())).toMatchObject({ outcome: "admitted" });
	});
});

describe("the caller's faults admitSession names, each driven", () => {
	it("refuses deps, a request and asks that are not objects, naming each", async () => {
		await expect(admitSession("deps" as never, request())).rejects.toThrow(
			/deps must be an object/,
		);
		await expect(admitSession(deps(), "request" as never)).rejects.toThrow(
			/the request must be an object/,
		);
		await expect(admitSession(deps(), request({ asks: "acr" as never }))).rejects.toThrow(
			/asks must be an object/,
		);
	});

	it("takes an action another resolver's requirement was issued as credential_change: an issued action is its own requirement's", async () => {
		const owner = met("mfa", { remediations: ["mfa.step_up"] });
		resolverForTests([owner], { actions: TEST_ACTIONS });
		const seen: string[] = [];
		const other = met("other", {
			admit: async ({ action }) => {
				seen.push(action.grade);
				return { outcome: "met" };
			},
		});
		await admitSession(
			deps({ requirements: resolverForTests([other], { actions: TEST_ACTIONS }) }),
			request({ action: issuedRemediationActions(owner)?.step_up as IssuedRemediationAction }),
		);
		expect(seen).toEqual(["credential_change"]);
	});
});
