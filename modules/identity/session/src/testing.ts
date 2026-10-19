import { cookiesFor } from "@mod/cookies";
import { type HttpRequest, site } from "@mod/http";
import { defineModule, isUnavailable, type Log, Unavailable } from "@mod/kernel";
import { keptAttributes, type SourcedAttributes } from "@mod/login-attributes";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import {
	type AuthContext,
	type Entry,
	type EntryLevel,
	entryRequirements,
	type LoginFacts,
	participants,
	type Session,
	type Sessions,
	sessionRules,
	sessions,
} from "./contract.ts";

export function stubSessions(parts: Partial<Sessions> = {}): Sessions {
	return {
		enter: async () => undefined,
		enterFor: async () => ({ kind: "absent" }),
		raise: async () => undefined,
		complete: async () => {
			throw new Error("not in this test");
		},
		close: async () => ({ kind: "closed", cookies: [] }),
		closeRequest: async () => ({ kind: "closed", cookies: [] }),
		entryOf: async () => ({ kind: "absent" }),
		recent: () => false,
		...parts,
	};
}

/**
 * A composition that offers sessions, as one implementation of the contract does. It composes an
 * entry requirement that answers short at `credentials` unless the session holds the amr
 * `strong`, and a participant in closing whose work can be made to fail.
 */
export interface SessionsPlace {
	readonly sessions: Sessions;
	now(): number;
	advance(ms: number): void;
	readonly lifetimeMs: number;
	/** A browser's request carrying the cookies these `Set-Cookie` values set. */
	request(setCookies?: readonly string[]): HttpRequest;
	revokeSubject(subject: string): Promise<{ readonly complete: boolean }>;
	/** How many sessions a subject's listing holds before a login pushes one out. */
	readonly listingCap: number;
	/** Makes the next write to a subject's listing fail as unavailable. */
	failNextListing(): void;
	/** Subjects whose sessions the participant finished closing. */
	readonly closed: readonly string[];
	failClosing(on: boolean): void;
}

/** How a place opens: with a requirement that judges changing credentials (the default), or with none. */
export interface PlaceOptions {
	readonly credentialsJudged?: boolean;
}

/** What every implementation of sessions must do, as a caller sees it. */
export function sessionsContract(
	name: string,
	open: (options?: PlaceOptions) => Promise<SessionsPlace>,
): void {
	const facts = (place: SessionsPlace, subject = "alice") => ({
		subject,
		amr: ["pwd"],
		authenticatedAt: place.now(),
	});
	describe(`sessions' contract: ${name}`, () => {
		it("lets a session change credentials, where nothing judges that, only after a recent sign-in at a known time", async () => {
			const place = await open({ credentialsJudged: false });
			const entering = async (authenticatedAt: number | "unknown") => {
				const at = { subject: "alice", amr: ["pwd"], authenticatedAt };
				const done = await place.sessions.complete(place.request(), at);
				return (await place.sessions.enterFor(place.request(done.cookies), "credentials")).kind;
			};
			expect(await entering("unknown")).toBe("short");
			expect(await entering(place.now() - 301_000)).toBe("short");
			expect(await entering(place.now())).toBe("entered");
		});

		it("tells whether a time is recent by one window, 300 seconds unless set otherwise", async () => {
			const place = await open();
			const window = sessionRules.credentialsSecondsDefault * 1000;
			expect([
				place.sessions.recent(place.now()),
				place.sessions.recent(place.now() - window),
				place.sessions.recent(place.now() - window - 1),
			]).toEqual([true, true, false]);
		});

		it("opens a session on login behind a new cookie, which enters it", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const entered = await place.sessions.enter(place.request(done.cookies));
			expect(entered?.id).toBe(done.session.id);
			expect(entered?.context).toMatchObject({
				subject: "alice",
				amr: ["pwd"],
				authenticatedAt: place.now(),
			});
			expect(entered?.context.authenticatedAtUnknown).toBeUndefined();
			expect(await place.sessions.enter(place.request())).toBeUndefined();
		});

		it("closes the session a request carried when a login completes over it", async () => {
			const place = await open();
			const first = await place.sessions.complete(place.request(), facts(place));
			const second = await place.sessions.complete(
				place.request(first.cookies),
				facts(place, "bob"),
			);
			expect(second.session.id).not.toBe(first.session.id);
			expect(await place.sessions.enter(place.request(first.cookies))).toBeUndefined();
			expect(place.closed).toEqual(["alice"]);
		});

		it("keeps a session's subject for as long as it lives, a raise included, and never names another session by its handle", async () => {
			const place = await open();
			const first = await place.sessions.complete(place.request(), facts(place));
			const raised = await place.sessions.raise(place.request(first.cookies), ["strong"]);
			expect(raised?.session.context.subject).toBe("alice");
			expect(await place.sessions.entryOf(first.session.id)).toMatchObject({
				kind: "entered",
				session: { context: { subject: "alice" } },
			});
			const second = await place.sessions.complete(
				place.request(raised?.cookies),
				facts(place, "bob"),
			);
			expect((await place.sessions.entryOf(first.session.id)).kind).toBe("absent");
			expect(await place.sessions.entryOf(second.session.id)).toMatchObject({
				kind: "entered",
				session: { context: { subject: "bob" } },
			});
		});

		it("ends a session at its lifetime, and when its subject is revoked", async () => {
			const place = await open();
			const lived = await place.sessions.complete(place.request(), facts(place));
			const revoked = await place.sessions.complete(place.request(), facts(place, "bob"));
			await place.revokeSubject("bob");
			expect(await place.sessions.enter(place.request(revoked.cookies))).toBeUndefined();
			expect((await place.sessions.entryOf(revoked.session.id)).kind).toBe("absent");
			expect((await place.sessions.entryOf(revoked.session.id)).kind).toBe("absent");
			place.advance(place.lifetimeMs - 1);
			expect((await place.sessions.entryOf(lived.session.id)).kind).toBe("entered");
			place.advance(1);
			expect(await place.sessions.enter(place.request(lived.cookies))).toBeUndefined();
			expect((await place.sessions.entryOf(lived.session.id)).kind).toBe("absent");
		});

		it("answers by handle the entry its cookie would get: entered with its end, short at a level it falls short of, absent once closed or revoked", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const endsAt = done.session.context.authenticatedAt + place.lifetimeMs;
			expect(await place.sessions.entryOf(done.session.id)).toMatchObject({
				kind: "entered",
				session: { id: done.session.id, context: { subject: "alice" } },
				endsAt,
			});
			expect(await place.sessions.entryOf(done.session.id, "credentials")).toMatchObject({
				kind: "short",
			});
			expect((await place.sessions.entryOf(done.session.id, "none")).kind).toBe("entered");
			const revoked = await place.sessions.complete(place.request(), facts(place, "bob"));
			await place.revokeSubject("bob");
			expect(await place.sessions.entryOf(revoked.session.id)).toEqual({ kind: "absent" });
			await place.sessions.close(done.session.id);
			expect(await place.sessions.entryOf(done.session.id)).toEqual({ kind: "absent" });
			expect(await place.sessions.entryOf("x".repeat(43))).toEqual({ kind: "absent" });
		});

		it("tells an entered session when it ends: its opening and the lifetime in force", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			place.advance(1000);
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			const asked = place.request(raised?.cookies);
			const endsAt = done.session.context.authenticatedAt + place.lifetimeMs;
			expect(await place.sessions.enterFor(asked, "use")).toMatchObject({
				kind: "entered",
				endsAt,
			});
			expect(await place.sessions.entryOf(done.session.id)).toMatchObject({
				kind: "entered",
				endsAt: endsAt,
			});
			place.advance(endsAt - place.now() - 1);
			expect((await place.sessions.enterFor(asked, "use")).kind).toBe("entered");
			expect(await place.sessions.entryOf(done.session.id)).toMatchObject({
				kind: "entered",
				endsAt: endsAt,
			});
			place.advance(1);
			expect((await place.sessions.enterFor(asked, "use")).kind).toBe("absent");
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("absent");
		});

		it("asks the entry requirements at the level asked, and admits once a raise meets them", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const asked = place.request(done.cookies);
			expect((await place.sessions.enterFor(asked, "use")).kind).toBe("entered");
			expect(await place.sessions.enterFor(asked, "credentials")).toMatchObject({
				kind: "short",
				requirement: "test",
			});
			expect((await place.sessions.enterFor(place.request(), "use")).kind).toBe("absent");
			const raised = await place.sessions.raise(asked, ["strong"]);
			expect(raised?.raised).toBe(true);
			const afterRaise = place.request(raised?.cookies);
			expect((await place.sessions.enterFor(afterRaise, "credentials")).kind).toBe("entered");
		});

		it("raises under a new cookie, keeping the session and its authentication time", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			place.advance(1000);
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			expect(raised?.session.id).toBe(done.session.id);
			expect(raised?.session.context).toMatchObject({
				amr: expect.arrayContaining(["pwd", "strong"]),
				authenticatedAt: place.now() - 1000,
				raisedAt: place.now(),
				raisedAmr: ["strong"],
			});
			expect(await place.sessions.enter(place.request(done.cookies))).toBeUndefined();
			expect((await place.sessions.enter(place.request(raised?.cookies)))?.id).toBe(
				done.session.id,
			);
			expect(await place.sessions.raise(place.request(), ["strong"])).toBeUndefined();
		});

		it("keeps the authentication time a login reports, or that it is unknown, across a raise", async () => {
			const place = await open();
			const known = await place.sessions.complete(place.request(), {
				...facts(place),
				authenticatedAt: place.now() - 500,
			});
			expect(known.session.context.authenticatedAt).toBe(place.now() - 500);
			expect(known.session.context.authenticatedAtUnknown).toBeUndefined();
			const opened = place.now();
			const unknown = await place.sessions.complete(place.request(), {
				...facts(place, "bob"),
				authenticatedAt: "unknown",
			});
			place.advance(1000);
			const raised = await place.sessions.raise(place.request(unknown.cookies), ["strong"]);
			const entered = await place.sessions.enter(place.request(raised?.cookies));
			for (const context of [unknown.session.context, raised?.session.context, entered?.context]) {
				expect(context).toMatchObject({ authenticatedAt: opened, authenticatedAtUnknown: true });
			}
		});

		it("counts the lifetime and the revocation from the opening, not an earlier authentication time", async () => {
			const place = await open();
			await place.revokeSubject("alice");
			place.advance(60_000);
			const opened = place.now();
			const done = await place.sessions.complete(place.request(), {
				...facts(place),
				authenticatedAt: opened - 120_000,
			});
			expect(done.session.context.authenticatedAt).toBe(opened - 120_000);
			const endsAt = opened + place.lifetimeMs;
			const asked = place.request(done.cookies);
			expect(await place.sessions.enterFor(asked, "use")).toMatchObject({
				kind: "entered",
				endsAt,
			});
			const raised = await place.sessions.raise(asked, ["strong"]);
			place.advance(endsAt - place.now() - 1);
			expect(await place.sessions.enter(place.request(raised?.cookies))).toBeDefined();
			place.advance(1);
			expect(await place.sessions.enter(place.request(raised?.cookies))).toBeUndefined();
		});

		it("takes an authentication time later than the opening as the opening", async () => {
			const place = await open();
			const opened = place.now();
			const done = await place.sessions.complete(place.request(), {
				...facts(place),
				authenticatedAt: opened + 60_000,
			});
			expect(done.session.context.authenticatedAt).toBe(opened);
		});

		it("says what a raise added once each, however often it was given", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const raised = await place.sessions.raise(place.request(done.cookies), [
				"strong",
				"pwd",
				"strong",
			]);
			expect(raised?.session.context).toMatchObject({
				amr: ["pwd", "strong"],
				raisedAmr: ["strong", "pwd"],
			});
		});

		it("closes a session past its lifetime without calling the participants, its cookie gone with it", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			place.advance(place.lifetimeMs);
			for (const cookies of [done.cookies, raised?.cookies]) {
				const closed = await place.sessions.close(done.session.id, place.request(cookies));
				// What the close found (`from`) is the implementation's: a record gone, or one it ended.
				expect(closed).toMatchObject({ kind: "closed", cookies: [] });
				expect(closed.session).toBeUndefined();
			}
			expect(place.closed).toEqual([]);
		});

		it("hands out every session frozen", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const entered = await place.sessions.enter(place.request(done.cookies));
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			const entry = await place.sessions.enterFor(place.request(raised?.cookies), "use");
			const given = [
				done.session,
				entered,
				raised?.session,
				entry.kind === "entered" && entry.session,
			];
			expect(given.map((session) => Object.isFrozen(session))).toEqual([true, true, true, true]);
		});

		it("closes once every participant is done, and lets nobody in meanwhile", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			expect(await place.sessions.entryOf(done.session.id)).toMatchObject({
				kind: "entered",
				session: { context: { subject: "alice" } },
			});
			place.failClosing(true);
			expect((await place.sessions.close(done.session.id)).kind).toBe("pending");
			expect(await place.sessions.enter(place.request(done.cookies))).toBeUndefined();
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("absent");
			place.failClosing(false);
			expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
			expect(place.closed).toEqual(["alice"]);
			expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
			expect(place.closed).toEqual(["alice"]);
		});

		it("destroys the cookie on close by handle only when it opens that session", async () => {
			const place = await open();
			const mine = await place.sessions.complete(place.request(), facts(place));
			const other = await place.sessions.complete(place.request(), facts(place, "bob"));
			const asked = place.request(other.cookies);
			expect((await place.sessions.close(mine.session.id, asked)).cookies).toEqual([]);
			expect((await place.sessions.close(other.session.id, asked)).cookies).toEqual([
				expect.stringMatching(/Max-Age=0/i),
			]);
		});

		it("keeps the attributes a login gives under their source, as they were at login, until it closes", async () => {
			const place = await open();
			const values = {
				email: "alice@example.com",
				email_verified: true,
				name: "Alice",
				picture: "https://pictures.example/alice",
				groups: ["staff", "ops"],
			};
			const given = { source: "users", values };
			const done = await place.sessions.complete(place.request(), {
				...facts(place),
				attributes: given,
			});
			values.groups.push("admin");
			values.name = "Mallory";
			const kept = {
				source: "users",
				values: { ...values, name: "Alice", groups: ["staff", "ops"] },
			};
			expect(done.session.context.attributes).toEqual(kept);
			expect((await place.sessions.enter(place.request(done.cookies)))?.context.attributes).toEqual(
				kept,
			);
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			expect(raised?.session.context.attributes).toEqual(kept);
			const entry = await place.sessions.entryOf(done.session.id);
			expect(entry.kind === "entered" && entry.session.context.attributes).toEqual(kept);
			const bare = await place.sessions.complete(place.request(), facts(place, "bob"));
			expect(bare.session.context).not.toHaveProperty("attributes");
		});

		it("keeps a login's attributes as login-attributes keeps them, at login and on entry alike", async () => {
			const place = await open();
			const keptOf = async (given: unknown) => {
				const attributes = given as SourcedAttributes;
				const done = await place.sessions.complete(place.request(), {
					...facts(place),
					attributes,
				});
				const entered = await place.sessions.enter(place.request(done.cookies));
				expect(entered?.context.attributes).toEqual(done.session.context.attributes);
				return done.session.context.attributes;
			};
			const givens = [
				{ source: "users", values: { email: "a@b.example", name: "n".repeat(513), groups: [2] } },
				{ source: "users", values: { email: "a@", email_verified: true, name: "Al\u0000" } },
				{ source: "users", values: { picture: "http://p.example/a", name: "Al", role: "admin" } },
				{ source: "", values: { name: "Al" } },
				{ source: "users", values: null },
			];
			for (const given of givens) {
				expect(await keptOf(given), JSON.stringify(given)).toEqual(keptAttributes(given).kept);
			}
		});

		it("closes the session a request's cookie points to, and destroys the cookie", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const closed = await place.sessions.closeRequest(place.request(done.cookies));
			expect(closed.kind).toBe("closed");
			expect(closed.cookies.some((cookie) => /Max-Age=0/i.test(cookie))).toBe(true);
			expect(await place.sessions.enter(place.request(done.cookies))).toBeUndefined();
		});

		it("destroys a session cookie sent twice, reading neither and closing no session for it", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const once = done.cookies[0] as string;
			const twice = place.request([once, once]);
			expect(await place.sessions.enter(twice)).toBeUndefined();
			const closed = await place.sessions.closeRequest(twice);
			expect(closed).toMatchObject({
				kind: "closed",
				cookies: [expect.stringMatching(/Max-Age=0/i)],
			});
			expect(closed).not.toHaveProperty("session");
			expect(await place.sessions.enter(place.request(done.cookies))).toBeDefined();
		});

		it("destroys a cookie that opens nothing, and closes no session for it", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const raised = await place.sessions.raise(place.request(done.cookies), ["strong"]);
			const forged = (done.cookies[0] as string).replace(/=[^;]*/, `=${"A".repeat(43)}`);
			for (const stale of [done.cookies, [forged]]) {
				const closed = await place.sessions.closeRequest(place.request(stale));
				expect(closed).toMatchObject({
					kind: "closed",
					cookies: [expect.stringMatching(/Max-Age=0/i)],
				});
				expect(closed).not.toHaveProperty("session");
			}
			expect((await place.sessions.enter(place.request(raised?.cookies)))?.id).toBe(
				done.session.id,
			);
			expect(place.closed).toEqual([]);
			expect((await place.sessions.closeRequest(place.request())).cookies).toEqual([]);
		});

		it("closes every live session of a revoked subject, calling the participants, and no one else's", async () => {
			const place = await open();
			await place.sessions.complete(place.request(), facts(place));
			await place.sessions.complete(place.request(), facts(place));
			const other = await place.sessions.complete(place.request(), facts(place, "bob"));
			await place.revokeSubject("alice");
			expect(place.closed).toEqual(["alice", "alice"]);
			expect((await place.sessions.entryOf(other.session.id)).kind).toBe("entered");
		});

		it("answers a revocation incomplete while a close it made is left pending, and complete once finished", async () => {
			const place = await open();
			await place.sessions.complete(place.request(), facts(place));
			place.failClosing(true);
			expect(await place.revokeSubject("alice")).toEqual({ complete: false });
			place.failClosing(false);
			expect(await place.revokeSubject("alice")).toEqual({ complete: true });
			expect(place.closed).toEqual(["alice"]);
		});

		it("closes a session its subject's full listing pushes out, calling the participants", async () => {
			const place = await open();
			const first = await place.sessions.complete(place.request(), facts(place));
			const others = await place.sessions.complete(place.request(), facts(place, "bob"));
			for (let n = 0; n < place.listingCap; n++) {
				place.advance(1000);
				await place.sessions.complete(place.request(), facts(place));
			}
			expect(place.closed).toEqual(["alice"]);
			expect((await place.sessions.entryOf(first.session.id)).kind).toBe("absent");
			expect((await place.sessions.entryOf(others.session.id)).kind).toBe("entered");
		});

		it("fails a login whose session cannot be listed under its subject", async () => {
			const place = await open();
			place.failNextListing();
			await expect(place.sessions.complete(place.request(), facts(place))).rejects.toSatisfy(
				isUnavailable,
			);
			const done = await place.sessions.complete(place.request(), facts(place));
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("entered");
		});

		it("names a closed session for the lifetime from its last close", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			const named = { id: done.session.id, subject: "alice" };
			for (let n = 0; n < 3; n++) {
				expect((await place.sessions.close(done.session.id)).session).toEqual(named);
				place.advance(place.lifetimeMs - 1);
			}
		});

		it("says the state each close found the record in: open, closing while left pending, then closed", async () => {
			const place = await open();
			const done = await place.sessions.complete(place.request(), facts(place));
			place.failClosing(true);
			expect((await place.sessions.close(done.session.id)).from).toBe("open");
			expect((await place.sessions.close(done.session.id)).from).toBe("closing");
			place.failClosing(false);
			expect((await place.sessions.close(done.session.id)).from).toBe("closing");
			expect((await place.sessions.close(done.session.id)).from).toBe("closed");
			expect((await place.sessions.close("x".repeat(43))).from).toBeUndefined();
		});

		it("names the session a close ended or left pending, by its handle and subject", async () => {
			const place = await open();
			const named = (done: { session: Session }) => ({ id: done.session.id, subject: "alice" });
			const asked = await place.sessions.complete(place.request(), facts(place));
			expect((await place.sessions.closeRequest(place.request(asked.cookies))).session).toEqual(
				named(asked),
			);
			const pending = await place.sessions.complete(place.request(), facts(place));
			place.failClosing(true);
			expect(await place.sessions.close(pending.session.id)).toMatchObject({
				kind: "pending",
				session: named(pending),
			});
			place.failClosing(false);
			expect(await place.sessions.close(pending.session.id)).toMatchObject({
				kind: "closed",
				session: named(pending),
			});
		});
	});
}

/** How many sessions the stand-in lists under a subject before a login pushes one out. */
export const standInListingCap = 100;

/** How long a stand-in session lasts, counted from its opening. */
export const standInLifetimeSeconds = 3600;

/** What the stand-in keeps of a login's attributes, as login-attributes keeps them, logging dropped names. */
function keptAtLogin(given: unknown, log: Log): SourcedAttributes | undefined {
	const { kept, dropped, others } = keptAttributes(given);
	if (dropped.length > 0 || others > 0) {
		log.warn("session.attributes_dropped", { dropped: dropped.join(","), others });
	}
	return kept;
}

/** The authentication time the stand-in keeps from a login: the one reported, at most the opening. */
function authenticatedAtOf(
	facts: LoginFacts,
	openedAt: number,
	log: Log,
): Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown"> {
	const reported = facts.authenticatedAt;
	if (reported === "unknown") return { authenticatedAt: openedAt, authenticatedAtUnknown: true };
	if (reported > openedAt) log.warn("session.authentication_time_capped");
	return { authenticatedAt: Math.min(reported, openedAt) };
}

/** A session's amr once a raise adds `amr`, and what the raise added, each value once. */
function raisedBy(held: readonly string[], amr: readonly string[]) {
	const raisedAmr = [...new Set(amr)];
	return { amr: [...new Set([...held, ...raisedAmr])], raisedAmr };
}

/** Each stand-in's listing: the handles it lists under a subject, and a switch to fail its next write. */
const listingOf = new WeakMap<
	Sessions,
	{ members(subject: string): readonly string[]; failNext(): void }
>();

/** Makes the stand-in's next write to a subject's listing fail as unavailable. */
export function failStandInListing(stand: Sessions): void {
	listingOf.get(stand)?.failNext();
}

/**
 * A stand-in for tests of the modules that use sessions: records kept in memory on the
 * composition's clock, behind cookies by `cookies`' rule. It asks the contributed entry requirements and
 * subject revocation as the contract has it, and calls the participants when a session closes. A
 * pending close goes on only when it is asked again: there is no sweep. It lists each subject's
 * sessions as the contract has it, up to `standInListingCap`, and closes them through `close`
 * when the listing pushes one out or the subject is revoked.
 */
export const sessionStandIn = defineModule({ name: "session" }, (m) => [
	m.provide(sessions).by(async (c) => {
		const jar = cookiesFor((await c.get(site)).secureCookies);
		const revocation = await c.get(subjectRevocation);
		const shortOf = sessionRules.entryShortOf(await c.collect(entryRequirements), c.clock.now);
		const closers = await c.collect(participants);
		const lifetimeMs = standInLifetimeSeconds * 1000;
		type Kept = {
			context: AuthContext;
			state: "open" | "closing" | "closed";
			openedAt: number;
			until: number;
		};
		const kept = new Map<string, Kept>();
		/** The handle each cookie's secret opens, until the cookie ends. */
		const handles = new Map<string, { handle: string; until: number }>();
		/** Each subject's listing: when each listed handle ends. */
		const listing = new Map<string, Map<string, number>>();
		let failListing = false;
		const listedUnder = (subject: string) =>
			[...(listing.get(subject) ?? [])].filter(([, until]) => until > c.clock.now());
		/**
		 * Lists the session being opened until it ends, answering those pushed out over the cap: the
		 * others that end first. The session being opened is never pushed out.
		 */
		const list = (subject: string, handle: string, until: number) => {
			if (failListing) {
				failListing = false;
				throw new Unavailable("session");
			}
			const byEnd = listedUnder(subject).sort(
				([a, aEnds], [b, bEnds]) => aEnds - bEnds || (a < b ? -1 : a > b ? 1 : 0),
			);
			const over = Math.max(0, byEnd.length + 1 - standInListingCap);
			listing.set(subject, new Map([...byEnd.slice(over), [handle, until]]));
			return byEnd.slice(0, over).map(([pushed]) => pushed);
		};
		const random = () => Buffer.from(c.random.bytes(32)).toString("base64url");
		const handleOf = (secret: string | undefined) => {
			const found = secret === undefined ? undefined : handles.get(secret);
			return found && found.until > c.clock.now() ? found.handle : undefined;
		};
		/** The session cookie's value, when the request carries it once where it may be read. */
		const secretIn = (request: HttpRequest) => {
			const carried = jar.lookup(request, "session");
			return carried.kind === "found" ? carried.value : undefined;
		};
		const handleIn = (request: HttpRequest) => handleOf(secretIn(request));
		const sessionOf = (handle: string, found: Kept): Session =>
			Object.freeze({ id: handle, context: found.context });
		const liveAt = async (handle: string | undefined) => {
			const found = handle === undefined ? undefined : kept.get(handle);
			if (found?.state !== "open" || found.until <= c.clock.now()) return undefined;
			if ((await revocation.check(found.context.subject, found.openedAt)) === "revoked") {
				return undefined;
			}
			return found;
		};
		const enterAt = async (handle: string | undefined, level: EntryLevel): Promise<Entry> => {
			const found = await liveAt(handle);
			if (!found || handle === undefined) return { kind: "absent" };
			const short = await shortOf(found.context, level);
			if (short) return { kind: "short", ...short };
			const endsAt = found.openedAt + lifetimeMs;
			return { kind: "entered", session: sessionOf(handle, found), endsAt };
		};
		const enteredAt = async (handle: string | undefined) => {
			const entry = await enterAt(handle, "use");
			return entry.kind === "entered" ? entry : undefined;
		};
		const close = async (handle: string, request?: HttpRequest) => {
			const removed = request && handleIn(request) === handle ? [jar.write("session", "", 0)] : [];
			const found = kept.get(handle);
			// A record past its lifetime is gone; a closing one is kept until it is closed.
			if (!found || (found.state !== "closing" && found.until <= c.clock.now())) {
				return { kind: "closed" as const, cookies: removed };
			}
			const session = { id: handle, subject: found.context.subject };
			const from = found.state;
			if (found.state !== "closed") {
				found.state = "closing";
				const failed = await sessionRules.failedParticipants(closers, sessionOf(handle, found));
				for (const failure of failed) c.log.warn("session.participant_failed", failure);
				if (failed.length > 0) return { kind: "pending" as const, cookies: removed, session, from };
			}
			// A closed record is kept for the lifetime from its last close, and no longer listed.
			found.state = "closed";
			found.until = c.clock.now() + lifetimeMs;
			listing.get(found.context.subject)?.delete(handle);
			return { kind: "closed" as const, cookies: removed, session, from };
		};
		const stand: Sessions = {
			recent: (at) => c.clock.now() - at <= sessionRules.credentialsSecondsDefault * 1000,
			enter: async (request) => (await enteredAt(handleIn(request)))?.session,
			enterFor: (request, level) => enterAt(handleIn(request), level),
			entryOf: (handle, level = "use") => enterAt(handle, level),
			complete: async (request, facts) => {
				const carried = handleIn(request);
				if (carried !== undefined) await close(carried);
				const handle = random();
				const secret = random();
				const openedAt = c.clock.now();
				const attributes = keptAtLogin(facts.attributes, c.log);
				const context = Object.freeze({
					subject: facts.subject,
					amr: Object.freeze([...facts.amr]),
					...authenticatedAtOf(facts, openedAt, c.log),
					...(attributes === undefined ? {} : { attributes }),
				});
				const until = openedAt + lifetimeMs;
				kept.set(handle, { context, state: "open", openedAt, until });
				// Listed before its cookie is made; a session pushed out is closed through `close`.
				for (const pushed of list(facts.subject, handle, until)) await close(pushed);
				handles.set(secret, { handle, until });
				return {
					session: Object.freeze({ id: handle, context }),
					cookies: [jar.write("session", secret, lifetimeMs / 1000)],
				};
			},
			raise: async (request, amr) => {
				const secret = secretIn(request);
				const handle = handleOf(secret);
				const found = await liveAt(handle);
				if (!found || secret === undefined || handle === undefined) return undefined;
				handles.delete(secret);
				const next = random();
				handles.set(next, { handle, until: found.until });
				const raised = raisedBy(found.context.amr, amr);
				found.context = Object.freeze({
					...found.context,
					amr: Object.freeze(raised.amr),
					raisedAt: c.clock.now(),
					raisedAmr: Object.freeze(raised.raisedAmr),
				});
				const left = Math.max(1, Math.floor((found.until - c.clock.now()) / 1000));
				return {
					session: sessionOf(handle, found),
					cookies: [jar.write("session", next, left)],
					raised: true,
				};
			},
			closeRequest: async (request) => {
				const handle = handleIn(request);
				const carried = jar.lookup(request, "session").kind !== "absent";
				const removed = carried ? [jar.write("session", "", 0)] : [];
				if (handle === undefined) return { kind: "closed", cookies: removed };
				return { ...(await close(handle)), cookies: removed };
			},
			close,
		};
		listingOf.set(stand, {
			members: (subject) => listedUnder(subject).map(([handle]) => handle),
			failNext: () => {
				failListing = true;
			},
		});
		return stand;
	}),
	m.contribute(revocationFollowers).by((c) => {
		const lateSessions = c.late(sessions);
		const members = async (subject: string) =>
			(listingOf.get(lateSessions())?.members(subject) ?? []).map((member) => ({ member }));
		return {
			name: "session",
			follow: (subject) =>
				sessionRules.closeListed(subject, { members }, (handle) => lateSessions().close(handle)),
		};
	}),
]);
