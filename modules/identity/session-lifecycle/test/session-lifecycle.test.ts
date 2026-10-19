import { cookies } from "@mod/cookies";
import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Session, sessions } from "@mod/session";
import { participants } from "@mod/session-participants";
import sessionParticipants from "@mod/session-participants/module";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { beforeEach, describe, expect, it } from "vitest";
import sessionLifecycle from "../src/module.ts";
import type { StoredSession } from "../src/store.ts";
import { type SessionLifecycleSettings, sessionLifecycleConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

const start = 1_800_000_000_000;
let now = start;
beforeEach(() => {
	now = start;
});
const runtime = quietRuntime({ clock: { now: () => now } });
const facts = (subject = "alice") => ({ subject, amr: ["pwd"], authenticatedAt: now });
const pair = (setCookie: string | undefined) => setCookie?.split(";")[0] ?? "";
const secretIn = (setCookie: string | undefined) => pair(setCookie).split("=")[1] ?? "";
/** The handles the stores list under the subject, sorted. */
const listed = async (stores: ReturnType<typeof memoryStores>, subject: string) =>
	(await stores.listed.members(subject)).map(({ member }) => member).sort();
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** Long enough for one sweep at "sweep-interval": "1s". */
const oneSweep = () => pause(1300);
/** Long enough for a whole sweep to start and finish after the clock moves. */
const nextSweep = () => pause(2300);
const configWith = (settings: Partial<SessionLifecycleSettings> = {}) => ({
	...kernelConfig(),
	...httpConfig({ "public-origin": "https://as.example" }),
	...sessionLifecycleConfig(settings),
});

interface Closer {
	failing: boolean;
	calls: number;
	done: string[];
	gate?: Promise<void> | undefined;
}

async function boot(
	settings: Partial<SessionLifecycleSettings> = {},
	extra: Module[] = [],
	parts: Partial<Runtime> = {},
) {
	const stores = memoryStores();
	const closer: Closer = { failing: false, calls: 0, done: [] };
	const participant = defineModule({ name: "closer" }, (m) => [
		m.contribute(participants).by(() => ({
			name: "closer",
			closing: async (s) => {
				closer.calls++;
				const gate = closer.gate;
				if (gate) await gate;
				if (closer.failing) throw new Error("not yet");
				closer.done.push(s.context.subject);
			},
		})),
	]);
	/** Another host over the same stores and participant, under its own settings. */
	const configured = (given: Partial<SessionLifecycleSettings>) =>
		assemble({
			modules: [
				http,
				cookiesModule,
				sessionLifecycle,
				sessionRequirements,
				sessionParticipants,
				subjectRevocationStandIn,
				stores.module,
				participant,
				...extra,
			],
			config: configWith(given),
			runtime: quietRuntime({ clock: { now: () => now }, ...parts }),
		});
	const app = await configured(settings);
	await app.start();
	const s = app.get(sessions);
	const withCookie = (cookie: string, scheme: "http" | "https" = "https") =>
		testRequest({ headers: new Map([["cookie", cookie]]), source: { scheme } });
	const login = async (subject = "alice", request = testRequest()) =>
		pair((await s.complete(request, facts(subject))).cookies[0]);
	const jar = app.get(cookies);
	/** The handle the cookie enters (a TypeError when it enters nothing). */
	const handleOf = async (cookie: string) => ((await s.enter(withCookie(cookie))) as Session).id;
	return { app, s, stores, closer, withCookie, login, jar, handleOf, configured };
}

describe("session cookies", () => {
	it("opens a session behind its own cookie, holding an unguessable secret for its lifetime", async () => {
		const { s, withCookie, jar } = await boot();
		const { cookies: set } = await s.complete(testRequest(), facts());
		const secret = secretIn(set[0]);
		expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(set[0]).toBe(jar.write("session", secret, 3600));
		expect(await s.enter(withCookie(pair(set[0])))).toBeDefined();
		expect(await s.enter(withCookie(pair(jar.write("session", "forged", 1))))).toBeUndefined();
	});

	it("hands out a handle no cookie leads to directly, and reaches it through the cookie index by the secret", async () => {
		const { s, stores } = await boot();
		const { session, cookies } = await s.complete(testRequest(), facts());
		const secret = secretIn(cookies[0]);
		const handle = session.id;
		expect(handle).not.toBe(secret);
		expect(stores.kept.peek(handle)).toMatchObject({ format: 2, state: "open", subject: "alice" });
		expect(stores.index.peek(secret)).toBe(handle);
		expect(stores.kept.peek(secret)).toBeUndefined();
	});

	it("refuses to boot on a time that names no unit", async () => {
		const refused = await boot({ lifetime: 3600 as unknown as string }).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
			"session-lifecycle.lifetime",
		]);
	});

	it("refuses to boot where nothing keeps the entry requirements or the participants", async () => {
		const refused = await assemble({
			modules: [
				http,
				cookiesModule,
				sessionLifecycle,
				subjectRevocationStandIn,
				memoryStores().module,
			],
			config: configWith(),
			runtime,
		}).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["session.entry-judge"]);
	});

	it("uses the lifetime it is given, to the millisecond", async () => {
		const { s, withCookie, jar } = await boot({ lifetime: "2m" });
		const { cookies: set } = await s.complete(testRequest(), facts());
		expect(set[0]).toBe(jar.write("session", secretIn(set[0]), 120));
		const started = now;
		now = started + 119_999;
		expect(await s.enter(withCookie(pair(set[0])))).toBeDefined();
		now = started + 120_000;
		expect(await s.enter(withCookie(pair(set[0])))).toBeUndefined();
	});
});

describe("session attributes", () => {
	it("logs the names of the attributes a login gave that it dropped, never their values", async () => {
		const recorded = recordingLog();
		const { s } = await boot({}, [], { log: recorded.log });
		const dropped = () =>
			recorded.lines().filter((line) => line.event === "session-lifecycle.attributes_dropped");
		const login = (attributes: unknown) =>
			s.complete(testRequest(), { ...facts(), attributes } as Parameters<typeof s.complete>[1]);
		await login(undefined);
		await login({ source: "users", values: { email: "a@b.example", email_verified: true } });
		expect(dropped()).toEqual([]);
		const values = {
			email: "a@b.example",
			email_verified: "secret-flag",
			emailVerified: true,
			name: "n".repeat(513),
			role: "secret-role",
			"secret-key": 1,
			toString: "secret-text",
		};
		await login({ source: "users", values });
		await login({ source: "", values: { name: "secret-name" } });
		expect(dropped().map((line) => line.fields)).toEqual([
			{ dropped: "email_verified,name", others: 4 },
			{ dropped: "source,name", others: 0 },
		]);
		await login({
			source: "users",
			values: { email: "secret@", picture: "http://secret.example/" },
		});
		expect(dropped().at(-1)?.fields).toEqual({ dropped: "email,picture", others: 0 });
		await login({ source: "users", values: { email: "a@b.example", "secret-only": 1 } });
		expect(dropped().at(-1)?.fields).toEqual({ dropped: "", others: 1 });
		expect(JSON.stringify(recorded.lines())).not.toMatch(/secret|nnn/);
	});

	it("rechecks a record's attributes on every read", async () => {
		const { s, withCookie, stores, login, handleOf } = await boot();
		const cookie = await login();
		await stores.kept.records.change(await handleOf(cookie), (r) => ({
			value: {
				...(r as object),
				attributes: { source: "users", values: { email: "a@b.example", name: "n".repeat(513) } },
			} as unknown as StoredSession,
		}));
		const attributes = (await s.enter(withCookie(cookie)))?.context.attributes;
		expect(attributes).toEqual({ source: "users", values: { email: "a@b.example" } });
		expect(Object.isFrozen(attributes?.values)).toBe(true);
	});
});

describe("session authentication time", () => {
	it("keeps that a login's authentication time is unknown in the record, and nothing when it is known", async () => {
		const { s, stores } = await boot();
		const unknown = await s.complete(testRequest(), { ...facts(), authenticatedAt: "unknown" });
		const known = await s.complete(testRequest(), facts());
		expect(stores.kept.peek(unknown.session.id)).toMatchObject({
			format: 2,
			authenticatedAt: now,
			authenticatedAtUnknown: true,
		});
		expect(stores.kept.peek(known.session.id)).not.toHaveProperty("authenticatedAtUnknown");
	});

	it("keeps the opening apart from an earlier authentication time, and gives a raised cookie what is left from the opening", async () => {
		const { s, stores, withCookie, jar } = await boot();
		const done = await s.complete(testRequest(), { ...facts(), authenticatedAt: now - 1_000_000 });
		expect(stores.kept.peek(done.session.id)).toMatchObject({
			format: 2,
			openedAt: now,
			authenticatedAt: now - 1_000_000,
		});
		now += 5000;
		const raised = await s.raise(withCookie(pair(done.cookies[0])), ["otp"]);
		expect(raised?.cookies[0]).toBe(jar.write("session", secretIn(raised?.cookies[0]), 3595));
	});

	it("logs only that it capped an authentication time later than the opening", async () => {
		const recorded = recordingLog();
		const { s } = await boot({}, [], { log: recorded.log });
		await s.complete(testRequest(), facts());
		const done = await s.complete(testRequest(), { ...facts(), authenticatedAt: now + 60_000 });
		expect(done.session.context.authenticatedAt).toBe(now);
		const capped = recorded
			.lines()
			.filter((line) => line.event === "session-lifecycle.authentication_time_capped");
		expect(capped).toHaveLength(1);
		expect(JSON.stringify(capped)).not.toContain(String(now));
		expect(JSON.stringify(capped)).not.toContain("alice");
	});

	it("reads a record of the format before as one whose authentication time is unknown, and writes it back in its own", async () => {
		const { s, stores, withCookie, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		await stores.kept.records.change(handle, (r) => {
			const { openedAt: _, ...before } = r as unknown as Record<string, unknown>;
			return { value: { ...before, format: 1 } as unknown as StoredSession };
		});
		const entered = await s.enter(withCookie(cookie));
		expect(entered?.context).toMatchObject({ authenticatedAt: now, authenticatedAtUnknown: true });
		const raised = await s.raise(withCookie(cookie), ["otp"]);
		expect(raised?.raised).toBe(true);
		expect(stores.kept.peek(handle)).toMatchObject({
			format: 2,
			amr: ["pwd", "otp"],
			authenticatedAt: now,
			authenticatedAtUnknown: true,
			openedAt: now,
		});
		// Its opening is its authentication time: the lifetime ends from there.
		now += 3_600_000;
		expect(await s.enter(withCookie(pair(raised?.cookies[0])))).toBeUndefined();
	});

	it("lets nobody into a record of the format before that says its authentication time is unknown", async () => {
		const { s, stores, withCookie } = await boot();
		const done = await s.complete(testRequest(), { ...facts(), authenticatedAt: "unknown" });
		await stores.kept.records.change(done.session.id, (r) => {
			const { openedAt: _, ...before } = r as unknown as Record<string, unknown>;
			return { value: { ...before, format: 1 } as unknown as StoredSession };
		});
		expect(await s.enter(withCookie(pair(done.cookies[0])))).toBeUndefined();
	});
});

describe("session entry", () => {
	it("gives every login a new session and closes the one the request carried", async () => {
		const { s, withCookie, login } = await boot();
		const first = await login();
		const second = await login("alice", withCookie(first));
		expect(second).not.toBe(first);
		expect(await s.enter(withCookie(first))).toBeUndefined();
		expect(await s.enter(withCookie(second))).toBeDefined();
	});

	it("tells by handle the entry a session gives its holder", async () => {
		const { s, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		expect(await s.entryOf(handle)).toMatchObject({
			kind: "entered",
			session: { context: { subject: "alice", amr: ["pwd"] } },
		});
		await s.close(handle);
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect((await s.entryOf("unknown")).kind).toBe("absent");
	});

	it("lets nobody in whose subject is revoked while the entry requirements are asked", async () => {
		const asked: { gate?: Promise<void>; reached?: () => void } = {};
		const waiting = defineModule({ name: "waiting" }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "waiting",
				judges: ["use"],
				admits: async () => {
					asked.reached?.();
					await asked.gate;
					return { kind: "admit" };
				},
			})),
		]);
		const { s, withCookie, login, app } = await boot({}, [waiting]);
		const a = await login("alice");
		now += 60_000;
		let open = () => {};
		asked.gate = new Promise((resolve) => {
			open = resolve;
		});
		const reached = new Promise<void>((resolve) => {
			asked.reached = resolve;
		});
		const entering = s.enterFor(withCookie(a), "use");
		await reached;
		await app.get(subjectRevocation).revoke("alice");
		open();
		expect(await entering).toEqual({ kind: "absent" });
	});

	it("lets nobody in past the subject's revocation", async () => {
		const { s, withCookie, login, app } = await boot();
		const a = await login("alice");
		const b = await login("bob");
		now += 60_000;
		await app.get(subjectRevocation).revoke("alice");
		now += 60_000;
		expect(await s.enter(withCookie(a))).toBeUndefined();
		expect(await s.enter(withCookie(b))).toBeDefined();
		expect(await s.enter(withCookie(await login("alice")))).toBeDefined();
	});

	it("closes a session a read finds ended by the lifetime in force, so restoring the lifetime never brings it back", async () => {
		const { s, withCookie, stores, closer, login, handleOf, configured } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		const shorter = (await configured({ lifetime: "1m" })).get(sessions);
		now += 100_000;
		expect(await shorter.enter(withCookie(cookie))).toBeUndefined();
		expect(stores.kept.peek(handle)).toMatchObject({ state: "closed" });
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect(closer.calls).toBe(0);
	});

	it("closes on a read only a record still open, leaving one a close took meanwhile to its participants", async () => {
		const { stores, withCookie, login, handleOf, configured } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		const shorter = (await configured({ lifetime: "1m" })).get(sessions);
		now += 60_000;
		stores.kept.raceNextChange(
			(r) => ({ ...(r as object), state: "closing" }) as unknown as StoredSession,
		);
		expect(await shorter.enter(withCookie(cookie))).toBeUndefined();
		expect(stores.kept.peek(handle)).toMatchObject({ state: "closing" });
	});

	it("fails an entry closed when the cookie index cannot tell", async () => {
		const { s, stores, withCookie, login } = await boot();
		const cookie = await login();
		stores.down.cookies.failNext("read");
		await expect(s.enter(withCookie(cookie))).rejects.toSatisfy(isUnavailable);
		expect(await s.enter(withCookie(cookie))).toBeDefined();
	});

	it("answers unavailable, never a refusal, when the session store cannot tell", async () => {
		const { s, stores, withCookie, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		const asks = [
			() => s.enter(withCookie(cookie)),
			() => s.enterFor(withCookie(cookie), "use"),
			() => s.entryOf(handle),
			() => s.raise(withCookie(cookie), ["otp"]),
		];
		for (const ask of asks) {
			stores.down.sessions.failNext("read");
			await expect(ask()).rejects.toSatisfy(isUnavailable);
		}
		expect((await s.entryOf(handle)).kind).toBe("entered");
	});

	it("looks up only a cookie shaped as a secret", async () => {
		const { s, stores, withCookie, jar, login } = await boot();
		stores.down.cookies.failNext("read");
		for (const value of ["forged", "A".repeat(42), "A".repeat(44), `${"A".repeat(42)}.`]) {
			expect(await s.enter(withCookie(pair(jar.write("session", value, 1))))).toBeUndefined();
		}
		await expect(s.enter(withCookie(await login()))).rejects.toSatisfy(isUnavailable);
	});

	it("never hands out a handle or a secret that is already taken", async () => {
		// Each draw of randomness repeats one byte: handles and secrets collide where the order says.
		const order = [1, 2, 1, 3, 2];
		const random = { bytes: (n: number) => new Uint8Array(n).fill(order.shift() ?? 9) };
		const { s, withCookie, login } = await boot({}, [], { random });
		const first = await login();
		for (const subject of ["bob", "carol"]) {
			await expect(s.complete(testRequest(), facts(subject))).rejects.toSatisfy(isUnavailable);
		}
		expect((await s.enter(withCookie(first)))?.context.subject).toBe("alice");
	});

	it("fails an entry closed when subject revocation cannot tell", async () => {
		const withCookie = (cookie: string) =>
			testRequest({ headers: new Map([["cookie", cookie]]), source: { scheme: "https" } });
		const failing = defineModule({ name: "subject-revocation" }, (m) => [
			m.provide(subjectRevocation).by(() => ({
				revoke: async () => {},
				check: async () => {
					throw new Error("cannot tell");
				},
			})),
		]);
		const other = await assemble({
			modules: [
				http,
				cookiesModule,
				sessionLifecycle,
				sessionRequirements,
				sessionParticipants,
				failing,
				memoryStores().module,
			],
			config: configWith(),
			runtime,
		});
		const { cookies } = await other.get(sessions).complete(testRequest(), facts());
		await expect(other.get(sessions).enter(withCookie(pair(cookies[0])))).rejects.toThrow(
			"cannot tell",
		);
	});

	it("fails a login closed when the session it replaces cannot even be added to the closings", async () => {
		const { s, stores, withCookie, login } = await boot();
		const first = await login();
		stores.down.closing.failNext("add");
		await expect(s.complete(withCookie(first), facts())).rejects.toSatisfy(isUnavailable);
		expect(await s.enter(withCookie(first))).toBeDefined();
	});

	it("lets a session change credentials, where no requirement judges that, when its sign-in is as recent as recent-authentication asks", async () => {
		const { s, withCookie, login } = await boot({ "recent-authentication": "1m" });
		const cookie = await login();
		now += 60_000;
		expect((await s.enterFor(withCookie(cookie), "credentials")).kind).toBe("entered");
		now += 1;
		expect(await s.enterFor(withCookie(cookie), "credentials")).toEqual({
			kind: "short",
			requirement: "session",
			answer: { error: "step_up_required" },
		});
		expect((await s.enterFor(withCookie(cookie), "use")).kind).toBe("entered");
	});

	it("lets a session in only where every entry requirement admits it at the level asked, and says which fell short", async () => {
		const asked: string[] = [];
		const requirement = defineModule({ name: "requirement" }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "recent",
				judges: ["use", "credentials"],
				admits: async (context, level) => {
					asked.push(level);
					if (level === "credentials" && !context.amr.includes("otp")) {
						return { kind: "short" as const, answer: { needs: "otp" } };
					}
					if (level === "use" && context.subject === "mallory") {
						return { kind: "short" as const, answer: { needs: "nothing" } };
					}
					return { kind: "admit" as const };
				},
			})),
		]);
		const { s, withCookie, login } = await boot({}, [requirement]);
		const cookie = await login();
		expect(await s.enterFor(withCookie(cookie), "credentials")).toEqual({
			kind: "short",
			requirement: "recent",
			answer: { needs: "otp" },
		});
		expect((await s.enterFor(withCookie(cookie), "use")).kind).toBe("entered");
		expect(await s.enter(withCookie(cookie))).toBeDefined();
		expect(asked).toContain("use");
		const barred = await login("mallory");
		expect((await s.enterFor(withCookie(barred), "none")).kind).toBe("entered");
		expect(await s.enter(withCookie(barred))).toBeUndefined();
		expect(await s.enterFor(withCookie(""), "use")).toEqual({ kind: "absent" });
	});

	it("answers a request without a session cookie absent without reading the session store", async () => {
		const { s, stores } = await boot();
		stores.down.sessions.unavailable("read");
		expect(await s.enterFor(testRequest(), "use")).toEqual({ kind: "absent" });
		expect(await s.enter(testRequest())).toBeUndefined();
	});
});

describe("session closing", () => {
	it("stays closing until every participant has finished, and clears only its own cookie", async () => {
		const { s, withCookie, closer, login, jar, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		closer.failing = true;
		expect((await s.close(handle, withCookie(cookie))).kind).toBe("pending");
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		closer.failing = false;
		expect(
			await s.close(handle, withCookie(pair(jar.write("session", "o".repeat(43), 1)))),
		).toEqual({
			kind: "closed",
			cookies: [],
			session: { id: handle, subject: "alice" },
			from: "closing",
		});
		expect((await s.close(handle, withCookie(cookie))).cookies[0]).toBe(
			jar.write("session", "", 0),
		);
	});

	it("lets nobody in, by cookie or by handle, while a close's participants are still running", async () => {
		const { s, withCookie, closer, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		const closing = s.close(handle);
		await pause(10);
		expect(closer.calls).toBe(1);
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect(await s.raise(withCookie(cookie), ["otp"])).toBeUndefined();
		gate.resolve();
		expect((await closing).kind).toBe("closed");
	});

	it("logs a participant that fails a close by its name and the error's kind", async () => {
		const recorded = recordingLog();
		const { s, closer, login, handleOf } = await boot({}, [], { log: recorded.log });
		const handle = await handleOf(await login());
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		const failed = recorded
			.lines()
			.filter((l) => l.event === "session-lifecycle.participant_failed");
		expect(failed.map((line) => line.fields)).toEqual([{ participant: "closer", kind: "Error" }]);
	});

	it("never moves back from closed when two closes overlap", async () => {
		const { s, closer, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		const first = s.close(handle);
		await pause(10);
		closer.gate = undefined;
		expect((await s.close(handle)).kind).toBe("closed");
		closer.failing = true;
		gate.resolve();
		expect((await first).kind).toBe("pending");
		const calls = closer.calls;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.calls).toBe(calls);
	});

	it("keeps a pending closing past the session's lifetime and finishes it without the user", async () => {
		const { s, closer, login, app, handleOf } = await boot({
			lifetime: "1m",
			"sweep-interval": "1s",
		});
		const cookie = await login();
		const handle = await handleOf(cookie);
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		now += 120_000;
		closer.failing = false;
		const calls = closer.calls;
		await oneSweep();
		expect(closer.calls).toBeGreaterThan(calls);
		const after = closer.calls;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.calls).toBe(after);
		await app.stop(1000);
	});

	it("puts off only a record still closing, never one another close ended meanwhile", async () => {
		const { s, stores, closer, login, handleOf } = await boot();
		const handle = await handleOf(await login());
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		closer.failing = true;
		const first = s.close(handle);
		await pause(10);
		const mark = { format: 1, state: "closed" } as unknown as StoredSession;
		stores.kept.raceNextChange(() => mark);
		gate.resolve();
		expect((await first).kind).toBe("pending");
		expect(stores.kept.peek(handle)).toEqual(mark);
		closer.gate = undefined;
		expect((await s.close(handle)).kind).toBe("closed");
	});

	it("calls the participants when closing a session the lifetime in force has ended, as any close does", async () => {
		const { stores, closer, login, handleOf, configured } = await boot();
		const handle = await handleOf(await login());
		const shorter = (await configured({ lifetime: "1m" })).get(sessions);
		now += 60_000;
		expect(await shorter.close(handle)).toMatchObject({ kind: "closed", from: "open" });
		expect(closer.calls).toBe(1);
		// Closed already, or no record at all: the close says so, and calls no one again.
		expect((await shorter.close(handle)).from).toBe("closed");
		expect((await shorter.close("x".repeat(43))).from).toBeUndefined();
		expect(closer.calls).toBe(1);
		expect(stores.kept.peek(handle)).toMatchObject({ state: "closed" });
		expect(stores.kept.pending()).toEqual([]);
	});

	it("marks a session closed with a write even when there is no record", async () => {
		const { s, stores } = await boot();
		const handle = "x".repeat(43);
		stores.down.sessions.failNext("save");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect((await s.close(handle)).kind).toBe("closed");
		expect(stores.kept.peek(handle)).toEqual({ format: 2, state: "closed" });
	});

	it("keeps a closed record for the lifetime from its closing, then lets it go", async () => {
		const { s, stores, login, handleOf } = await boot({ lifetime: "1m" });
		const handle = await handleOf(await login());
		now += 30_000;
		expect((await s.close(handle)).kind).toBe("closed");
		now += 59_999;
		expect(stores.kept.peek(handle)).toMatchObject({ state: "closed" });
		now += 1;
		expect(stores.kept.peek(handle)).toBeUndefined();
	});

	it("lets nobody into a record of a format it does not know, and neither closes it nor logs in over its cookie", async () => {
		const { s, withCookie, stores, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		await stores.kept.records.change(handle, (r) => ({
			value: { ...(r as object), format: 3 } as unknown as StoredSession,
		}));
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		// As an older host meets a record a newer one wrote: the cookie is left as it is.
		await expect(s.closeRequest(withCookie(cookie))).rejects.toSatisfy(isUnavailable);
		await expect(s.complete(withCookie(cookie), facts())).rejects.toSatisfy(isUnavailable);
		expect(stores.index.peek(cookie.split("=")[1] ?? "")).toBe(handle);
		expect(stores.kept.peek(handle)).toMatchObject({ format: 3, state: "open" });
	});

	it("lets nobody into a record of a shape it does not know", async () => {
		const { s, withCookie, stores, login, handleOf } = await boot();
		const odd = [
			{ extra: true },
			{ amr: "pwd" },
			{ authenticatedAt: String(now) },
			{ authenticatedAtUnknown: false },
			{ openedAt: undefined },
			{ attributes: { source: "users", values: { role: "admin" } } },
		];
		for (const change of odd) {
			const cookie = await login();
			await stores.kept.records.change(await handleOf(cookie), (r) => ({
				value: { ...(r as object), ...change } as unknown as StoredSession,
			}));
			expect(await s.enter(withCookie(cookie))).toBeUndefined();
		}
		const paused = await handleOf(await login());
		await stores.kept.records.change(paused, (r) => ({
			value: { ...(r as object), state: "paused" } as unknown as StoredSession,
		}));
		await expect(s.close(paused)).rejects.toSatisfy(isUnavailable);
		const handle = "m".repeat(43);
		const mark = { format: 1, state: "closed", extra: true } as unknown as StoredSession;
		await stores.kept.records.create(handle, mark, 60_000);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
	});

	it("puts off a closing whose record it cannot read, as one whose participants fail", async () => {
		const recorded = recordingLog();
		const { s, stores, login, app, handleOf } = await boot({ "sweep-interval": "1s" }, [], {
			log: recorded.log,
		});
		const failures = () =>
			recorded.lines().filter((line) => line.event === "session-lifecycle.sweep_failed");
		const handle = await handleOf(await login());
		await stores.kept.records.change(handle, (r) => ({
			value: { ...(r as object), format: 3 } as unknown as StoredSession,
		}));
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		await oneSweep();
		expect(failures()).toHaveLength(0);
		now += 1000;
		await nextSweep();
		expect(failures()).toHaveLength(1);
		// Put off by half its age on this host, counted from its first failure.
		now += 600_000;
		await nextSweep();
		expect(failures()).toHaveLength(2);
		now += 1000;
		await nextSweep();
		expect(failures()).toHaveLength(2);
		await app.stop(1000);
	}, 15_000);

	it("counts a closing's age afresh once a sweep finds it finished, when its record cannot be read again", async () => {
		const recorded = recordingLog();
		const { s, stores, login, app, handleOf } = await boot({ "sweep-interval": "1s" }, [], {
			log: recorded.log,
		});
		const ages = () =>
			recorded
				.lines()
				.filter((line) => line.event === "session-lifecycle.closing_pending")
				.map((line) => line.fields?.ageSeconds);
		const handle = await handleOf(await login());
		const format = (n: number) =>
			stores.kept.records.change(handle, (r) => ({
				value: { ...(r as object), format: n } as unknown as StoredSession,
			}));
		await format(3);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		await format(2);
		expect((await s.close(handle)).kind).toBe("closed");
		await oneSweep();
		now += 600_000;
		await format(3);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(ages()).toEqual([0, 0]);
		await app.stop(1000);
	});

	it("finishes a close that failed midway when it is asked again", async () => {
		const { s, withCookie, stores, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		stores.down.sessions.failNext("update");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		expect((await s.close(handle)).kind).toBe("closed");
		expect(stores.kept.pending()).toEqual([]);
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
	});

	it("sweeps at once a kept closing that stopped before it had a retry time", async () => {
		const { s, stores, closer, login, app, handleOf } = await boot({ "sweep-interval": "1s" });
		const handle = await handleOf(await login());
		stores.down.sessions.failNext("update");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		await oneSweep();
		expect(stores.kept.pending()).toEqual([]);
		expect(closer.done).toEqual(["alice"]);
		await app.stop(1000);
	});

	it("puts off a closing that keeps failing by half its age, up to an hour, and sweeps it only once due", async () => {
		const { s, closer, stores, login, app, handleOf } = await boot({
			"sweep-interval": "1s",
		});
		const handle = await handleOf(await login());
		const retryAt = () => (stores.kept.peek(handle) as unknown as { retryAt: number }).retryAt;
		closer.failing = true;
		const started = now;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(started + 1000);
		now += 600_000;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(now + 300_000);
		now += 7_200_000;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(now + 3_600_000);
		const calls = closer.calls;
		await oneSweep();
		expect(closer.calls).toBe(calls);
		now = retryAt();
		await oneSweep();
		expect(closer.calls).toBeGreaterThan(calls);
		await app.stop(1000);
	});

	it("stops sweeping when the host stops, once the closing under way is done", async () => {
		const { s, closer, login, app, handleOf } = await boot({ "sweep-interval": "1s" });
		closer.failing = true;
		for (const subject of ["alice", "bob"]) {
			const handle = await handleOf(await login(subject));
			expect((await s.close(handle)).kind).toBe("pending");
		}
		closer.failing = false;
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		now += 2000;
		await oneSweep();
		const stopping = app.stop(5000);
		closer.gate = undefined;
		gate.resolve();
		await stopping;
		expect(closer.done).toHaveLength(1);
	});

	it("lets a login succeed when the earlier session cannot be closed yet, and finishes that closing later", async () => {
		const { s, withCookie, closer, login, app } = await boot({ "sweep-interval": "1s" });
		const first = await login();
		closer.failing = true;
		const second = await login("alice", withCookie(first));
		expect(await s.enter(withCookie(second))).toBeDefined();
		expect(await s.enter(withCookie(first))).toBeUndefined();
		closer.failing = false;
		now += 2000;
		const calls = closer.calls;
		await oneSweep();
		expect(closer.calls).toBeGreaterThan(calls);
		await app.stop(1000);
	});

	it("goes on with the other pending closings when one fails in a sweep", async () => {
		const { s, stores, closer, login, app, handleOf } = await boot({
			"sweep-interval": "1s",
		});
		const handles = [];
		for (const subject of ["alice", "bob"]) {
			const cookie = await login(subject);
			handles.push(await handleOf(cookie));
		}
		closer.failing = true;
		for (const handle of handles) expect((await s.close(handle)).kind).toBe("pending");
		closer.failing = false;
		now += 2000;
		stores.down.sessions.failNext("read");
		await oneSweep();
		expect(closer.done).toHaveLength(1);
		now += 2000;
		await oneSweep();
		expect([...closer.done].sort()).toEqual(["alice", "bob"]);
		await app.stop(1000);
	});

	it("closes the session a request names whatever its state, clearing the cookie", async () => {
		const { s, withCookie, closer, login, jar, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		closer.failing = true;
		await s.close(handle);
		closer.failing = false;
		const done = await s.closeRequest(withCookie(cookie));
		expect(done.kind).toBe("closed");
		expect(done.cookies[0]).toBe(jar.write("session", "", 0));
		expect(await s.closeRequest(withCookie(""))).toEqual({ kind: "closed", cookies: [] });
	});
});

describe("session raise", () => {
	it("raises a session under a new cookie, keeps its handle and authentication time, and the old cookie no longer enters", async () => {
		const { s, withCookie, login, jar } = await boot();
		const cookie = await login();
		const before = (await s.enter(withCookie(cookie))) as Session;
		now += 5000;
		const raised = await s.raise(withCookie(cookie), ["otp", "mfa"]);
		expect(raised?.cookies[0]).toBe(jar.write("session", secretIn(raised?.cookies[0]), 3595));
		expect(raised?.session.id).toBe(before.id);
		expect(raised?.session.context).toMatchObject({
			amr: ["pwd", "otp", "mfa"],
			authenticatedAt: before.context.authenticatedAt,
		});
		expect(raised?.session.context.raisedAt).toBeGreaterThan(before.context.authenticatedAt);
		const fresh = pair(raised?.cookies[0]);
		expect(fresh).not.toBe(cookie);
		expect((await s.enter(withCookie(fresh)))?.context.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		expect(await s.raise(withCookie(cookie), ["otp"])).toBeUndefined();
		expect((await s.entryOf(before.id)).kind).toBe("entered");
		await s.close(before.id);
		expect(await s.raise(withCookie(fresh), ["otp"])).toBeUndefined();
	});

	it("leaves a raised session open when the cookie it replaced asks to log out", async () => {
		const { s, withCookie, closer, login } = await boot();
		const cookie = await login();
		const raised = await s.raise(withCookie(cookie), ["otp"]);
		const fresh = pair(raised?.cookies[0]);
		expect(await s.closeRequest(withCookie(cookie))).toMatchObject({ kind: "closed" });
		expect(closer.calls).toBe(0);
		expect((await s.enter(withCookie(fresh)))?.context.amr).toEqual(["pwd", "otp"]);
	});

	it("does not raise the session of a revoked subject", async () => {
		const { s, withCookie, login, app } = await boot();
		const cookie = await login();
		now += 1000;
		await app.get(subjectRevocation).revoke("alice");
		expect(await s.raise(withCookie(cookie), ["otp"])).toBeUndefined();
	});

	it("ends a session at the lifetime in force, even one opened under a longer one", async () => {
		const { withCookie, login, configured } = await boot();
		const cookie = await login();
		const later = await configured({ lifetime: "10m" });
		now += 599_999;
		expect(await later.get(sessions).enter(withCookie(cookie))).toBeDefined();
		now += 1;
		expect(await later.get(sessions).enter(withCookie(cookie))).toBeUndefined();
		expect(await later.get(sessions).raise(withCookie(cookie), ["otp"])).toBeUndefined();
	});

	it("writes a raised cookie by the policy in force, not the one at login", async () => {
		const { s, withCookie, login, configured } = await boot();
		const cookie = await login();
		const later = await configured({ lifetime: "10m" });
		now += 5000;
		const raised = await later.get(sessions).raise(withCookie(cookie), ["otp"]);
		const jar = later.get(cookies);
		expect(raised?.cookies).toEqual([jar.write("session", secretIn(raised?.cookies[0]), 595)]);
		expect(await s.enter(withCookie(pair(raised?.cookies[0])))).toBeDefined();
	});

	it("does not raise a session closed while the raise was under way", async () => {
		const { s, withCookie, stores, login, handleOf } = await boot();
		const cookie = await login();
		const handle = await handleOf(cookie);
		stores.kept.raceNextChange(
			(r) => ({ ...(r as object), state: "closing" }) as unknown as StoredSession,
		);
		expect(await s.raise(withCookie(cookie), ["otp"])).toBeUndefined();
		expect(stores.kept.peek(handle)).not.toHaveProperty("raisedAt");
	});

	it("gives a raised cookie at least a second, even at the session's end", async () => {
		const { s, withCookie, login, jar } = await boot({ lifetime: "1m" });
		const cookie = await login();
		now += 59_500;
		const raised = await s.raise(withCookie(cookie), ["otp"]);
		expect(raised?.cookies).toEqual([jar.write("session", secretIn(raised?.cookies[0]), 1)]);
	});

	it("indexes a raised cookie for at least a millisecond, even when the session ends during the raise", async () => {
		let ending = false;
		const moving = defineModule({ name: "subject-revocation" }, (m) => [
			m.provide(subjectRevocation).by(() => ({
				revoke: async () => {},
				// The clock reaches the session's end between the entry check and the new cookie.
				check: async () => {
					if (ending) now += 1;
					return "valid" as const;
				},
			})),
		]);
		// Each draw of randomness fills its bytes with one count: the handle, the secret, the raised secret.
		let draws = 0;
		const random = { bytes: (n: number) => new Uint8Array(n).fill(++draws) };
		const stores = memoryStores();
		const other = await assemble({
			modules: [
				http,
				cookiesModule,
				sessionLifecycle,
				sessionRequirements,
				sessionParticipants,
				moving,
				stores.module,
			],
			config: configWith({ lifetime: "1m" }),
			runtime: quietRuntime({ clock: { now: () => now }, random }),
		});
		const s = other.get(sessions);
		const { cookies } = await s.complete(testRequest(), facts());
		now += 59_999;
		ending = true;
		const request = testRequest({
			headers: new Map([["cookie", pair(cookies[0])]]),
			source: { scheme: "https" },
		});
		expect(await s.raise(request, ["otp"])).toBeUndefined();
		const raisedSecret = Buffer.from(new Uint8Array(32).fill(3)).toString("base64url");
		expect(stores.index.peek(raisedSecret)).toBeDefined();
	});

	it("gives a raised cookie what is left of the session's lifetime, and no more", async () => {
		const { s, withCookie, stores, login } = await boot({ lifetime: "1m" });
		const cookie = await login();
		now += 20_000;
		const raised = await s.raise(withCookie(cookie), ["otp"]);
		const secret = secretIn(raised?.cookies[0]);
		now += 39_999;
		expect(stores.index.peek(secret)).toBeDefined();
		now += 1;
		expect(stores.index.peek(secret)).toBeUndefined();
	});

	it("never lets the old cookie into a raised session, even when retiring it fails, and says what the raise added", async () => {
		const { s, stores, withCookie, login } = await boot();
		const cookie = await login();
		stores.down.cookies.failNext("remove");
		await expect(s.raise(withCookie(cookie), ["otp", "mfa"])).rejects.toSatisfy(isUnavailable);
		expect((await s.enter(withCookie(cookie)))?.context.amr).toEqual(["pwd"]);
		stores.down.sessions.failNext("update");
		const unraised = await s.raise(withCookie(cookie), ["otp", "mfa"]);
		expect(unraised?.raised).toBe(false);
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		const fresh = pair(unraised?.cookies[0]);
		expect((await s.enter(withCookie(fresh)))?.context.amr).toEqual(["pwd"]);
		const raised = await s.raise(withCookie(fresh), ["otp", "mfa"]);
		expect(raised?.raised).toBe(true);
		expect(raised?.session.context.raisedAmr).toEqual(["otp", "mfa"]);
		expect(raised?.session.context.amr).toEqual(["pwd", "otp", "mfa"]);
		const entered = (await s.enter(withCookie(pair(raised?.cookies[0]))))?.context;
		expect([Object.isFrozen(entered?.amr), Object.isFrozen(entered?.raisedAmr)]).toEqual([
			true,
			true,
		]);
	});
});

describe("each subject's sessions", () => {
	it("lists each login's session under its subject for its lifetime, and takes it off once closed", async () => {
		const { s, stores, login, handleOf } = await boot({ lifetime: "1m" });
		const first = await handleOf(await login());
		const second = await handleOf(await login());
		const other = await handleOf(await login("bob"));
		expect(await listed(stores, "alice")).toEqual([first, second].sort());
		expect(await listed(stores, "bob")).toEqual([other]);
		await s.close(first);
		expect(await listed(stores, "alice")).toEqual([second]);
		now += 60_000;
		expect(await listed(stores, "alice")).toEqual([]);
	});

	it("lets no session in past its listing, even once the lifetime in force is longer", async () => {
		const { stores, configured } = await boot();
		const shorter = await configured({ lifetime: "1m" });
		const { session } = await shorter.get(sessions).complete(testRequest(), facts());
		const longer = (await configured({ lifetime: "1h" })).get(sessions);
		now += 59_999;
		expect((await longer.entryOf(session.id)).kind).toBe("entered");
		now += 1;
		expect(await listed(stores, "alice")).toEqual([]);
		expect((await longer.entryOf(session.id)).kind).toBe("absent");
	});

	it("keeps a pending close listed until it is closed", async () => {
		const { s, stores, closer, login, handleOf } = await boot();
		const handle = await handleOf(await login());
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(await listed(stores, "alice")).toEqual([handle]);
		closer.failing = false;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(await listed(stores, "alice")).toEqual([]);
	});

	it("leaves no session anyone can enter unlisted when a login's write takes effect but its answer is lost", async () => {
		// Each draw of randomness fills its bytes with one count: the handle first, then the secret.
		for (const write of ["sessions.save", "listed.add", "cookies.save"] as const) {
			let draws = 0;
			const random = { bytes: (n: number) => new Uint8Array(n).fill(++draws) };
			const { s, stores } = await boot({}, [], { random });
			const [handle, secret] = [1, 2].map((n) =>
				Buffer.from(new Uint8Array(32).fill(n)).toString("base64url"),
			);
			stores.lost.add(write);
			await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
			const indexed = stores.index.peek(secret as string) !== undefined;
			expect(indexed).toBe(write === "cookies.save");
			if (indexed) expect(await listed(stores, "alice")).toEqual([handle]);
		}
	});

	it("fails a login whose session it cannot list", async () => {
		const { s, stores } = await boot();
		stores.down.listed.failNext("add");
		await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
	});

	it("closes a session all the same when it cannot be taken off the listing, logging it by kind", async () => {
		const recorded = recordingLog();
		const { s, stores, login, handleOf } = await boot({}, [], { log: recorded.log });
		const handle = await handleOf(await login());
		stores.down.listed.failNext("remove");
		expect((await s.close(handle)).kind).toBe("closed");
		const failed = recorded
			.lines()
			.filter((line) => line.event === "session-lifecycle.listing_failed");
		expect(failed.map((line) => line.fields)).toEqual([{ step: "remove", kind: "Unavailable" }]);
	});
});

describe("revoking a subject", () => {
	it("closes every listed session of the subject through close, so the participants run, and no one else's", async () => {
		const { app, s, stores, closer, login, withCookie } = await boot();
		const [first, second, other] = [await login(), await login(), await login("bob")];
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toEqual(["alice", "alice"]);
		expect(await listed(stores, "alice")).toEqual([]);
		expect(await s.enter(withCookie(first))).toBeUndefined();
		expect(await s.enter(withCookie(second))).toBeUndefined();
		expect(await s.enter(withCookie(other))).toBeDefined();
	});

	it("leaves a close whose participants fail pending and listed, to be finished like any other", async () => {
		const { app, s, stores, closer, login, handleOf } = await boot();
		const handle = await handleOf(await login());
		closer.failing = true;
		await app.get(subjectRevocation).revoke("alice");
		expect(await listed(stores, "alice")).toEqual([handle]);
		closer.failing = false;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.done).toEqual(["alice"]);
	});

	it("goes on past a close that fails, and fails the follower so the revocation logs it", async () => {
		const recorded = recordingLog();
		const { app, stores, closer, login } = await boot({}, [], { log: recorded.log });
		await login();
		await login();
		stores.down.closing.failNext("add");
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toEqual(["alice"]);
		// The listing answers in handle order, not login order, so either session may be the one left.
		expect(await listed(stores, "alice")).toHaveLength(1);
		const failed = recorded.lines().filter((l) => l.event === "subject-revocation.follower_failed");
		expect(failed.map((line) => line.fields)).toEqual([
			{ follower: "session-lifecycle", kind: "Unavailable" },
		]);
	});

	/** Fills alice's listing a second apart, after the session of `first`, and answers the cookies. */
	const fill = async (login: (subject?: string) => Promise<string>, cap: number) => {
		const cookies: string[] = [];
		for (let n = 0; n < cap; n++) {
			now += 1000;
			cookies.push(await login());
		}
		return cookies;
	};

	it("closes a session pushed out of a full listing through close, so the participants run, logging only the count", async () => {
		const recorded = recordingLog();
		const { s, stores, closer, login, withCookie } = await boot({}, [], { log: recorded.log });
		const first = await login();
		await fill(login, stores.listingCap);
		const pushed = recorded
			.lines()
			.filter((l) => l.event === "session-lifecycle.listing_pushed_out");
		expect(pushed).toEqual([
			{ level: "warn", event: "session-lifecycle.listing_pushed_out", fields: { count: 1 } },
		]);
		expect(await s.enter(withCookie(first))).toBeUndefined();
		expect(closer.done).toEqual(["alice"]);
	});

	it("lets the login in when a pushed-out close cannot finish yet, and the sweep finishes it", async () => {
		const { app, s, stores, closer, login, withCookie } = await boot({ "sweep-interval": "1s" });
		const first = await login();
		closer.failing = true;
		const [last] = (await fill(login, stores.listingCap)).slice(-1);
		expect(await s.enter(withCookie(last as string))).toBeDefined();
		expect(await s.enter(withCookie(first))).toBeUndefined();
		closer.failing = false;
		now += 2000;
		await oneSweep();
		expect(closer.done).toEqual(["alice"]);
		await app.stop(1000);
	});

	it("fails the login and puts the pushed-out session back when it cannot be kept for closing", async () => {
		const { app, s, stores, closer, login, handleOf } = await boot();
		const first = await handleOf(await login());
		await fill(login, stores.listingCap - 1);
		const before = await listed(stores, "alice");
		stores.down.closing.failNext("add");
		await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
		expect(await listed(stores, "alice")).toEqual(before);
		expect(before).toContain(first);
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toHaveLength(stores.listingCap);
	});

	it("never pushes out the session being opened, even under a full listing of longer sessions", async () => {
		const { stores, closer, login, handleOf, withCookie, configured } = await boot();
		const [first, ...rest] = await fill(login, stores.listingCap);
		const firstHandle = await handleOf(first as string);
		const shorter = (await configured({ lifetime: "1m" })).get(sessions);
		const { session, cookies } = await shorter.complete(testRequest(), facts());
		expect(await shorter.enter(withCookie(pair(cookies[0])))).toBeDefined();
		expect(closer.done).toEqual(["alice"]);
		const after = await listed(stores, "alice");
		expect(after).toHaveLength(rest.length + 1);
		expect(after).toContain(session.id);
		expect(after).not.toContain(firstHandle);
	});

	it("refuses the subject's sessions by the boundary even when their listing cannot be read", async () => {
		const { app, s, stores, closer, login, withCookie } = await boot();
		const cookie = await login();
		stores.down.listed.failNext("members");
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.calls).toBe(0);
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
	});
});
