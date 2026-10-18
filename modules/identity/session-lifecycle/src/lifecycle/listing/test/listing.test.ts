import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { participants, type Session, sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import { memoryStores } from "../../../../test/stores.ts";
import sessionLifecycle from "../../../module.ts";
import type { StoredSession } from "../../../store.ts";
import { sessionLifecycleConfig } from "../../../testing.ts";

let now = 1_800_000_000_000;
const facts = () => ({ subject: "alice", amr: ["pwd"], authenticatedAt: now });

async function boot(log = recordingLog()) {
	const stores = memoryStores();
	const closed: string[] = [];
	const closer = defineModule({ name: "closer" }, (m) => [
		m.contribute(participants).by(() => ({
			name: "closer",
			closing: async (s) => {
				closed.push(s.context.subject);
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			cookiesModule,
			sessionLifecycle,
			subjectRevocationStandIn,
			stores.module,
			closer,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...sessionLifecycleConfig(),
		},
		runtime: quietRuntime({ clock: { now: () => now }, log: log.log }),
	});
	await app.start();
	const s = app.get(sessions);
	const withCookie = (cookie: string) =>
		testRequest({ headers: new Map([["cookie", cookie]]), source: { scheme: "https" } });
	const login = async (given = facts()) =>
		(await s.complete(testRequest(), given)).cookies[0]?.split(";")[0] ?? "";
	const logged = (event: string) => log.lines().filter((line) => line.event === event);
	return { app, s, stores, closed, login, withCookie, logged };
}

it("puts a pushed-out session back for what it has left, so the next login pushes out that one again", async () => {
	const { s, stores, closed, login, withCookie } = await boot();
	const firstAt = now;
	const first = await login();
	const firstHandle = ((await s.enter(withCookie(first))) as Session).id;
	const cookies: string[] = [];
	for (let n = 0; n < stores.listingCap - 1; n++) {
		now += 1000;
		cookies.push(await login());
	}
	stores.down.closing.failNext("add");
	await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
	// The stand-in's listing also answers each member's time left.
	const kept = (await stores.listed.members("alice")) as readonly {
		member: string;
		remainingMs: number;
	}[];
	const back = kept.find(({ member }) => member === firstHandle);
	expect(back?.remainingMs).toBe(firstAt + 3_600_000 - now);
	now += 1000;
	await login();
	expect(await s.enter(withCookie(first))).toBeUndefined();
	expect(await s.enter(withCookie(cookies[0] as string))).toBeDefined();
	expect(closed).toEqual(["alice"]);
});

it("puts a pushed-out session back for what it has left from its opening, though it was authenticated long before", async () => {
	const { app, s, stores, closed, login, withCookie } = await boot();
	const firstAt = now;
	// Authenticated upstream two lifetimes before it opened here.
	const first = await login({ ...facts(), authenticatedAt: now - 7_200_000 });
	const firstHandle = ((await s.enter(withCookie(first))) as Session).id;
	for (let n = 0; n < stores.listingCap - 1; n++) {
		now += 1000;
		await login();
	}
	stores.down.closing.failNext("add");
	await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
	const kept = (await stores.listed.members("alice")) as readonly {
		member: string;
		remainingMs: number;
	}[];
	const back = kept.find(({ member }) => member === firstHandle);
	expect(back?.remainingMs).toBe(firstAt + 3_600_000 - now);
	// Listed again, so revoking the subject closes it too.
	await app.get(subjectRevocation).revoke("alice");
	expect(await s.enter(withCookie(first))).toBeUndefined();
	expect(closed).toHaveLength(stores.listingCap);
});

/** Fills alice's listing behind the session of `first`, then fails the login that pushes it out, as the closings refuse. */
async function pushOutRefused(
	{ s, stores, login }: Awaited<ReturnType<typeof boot>>,
	first: string,
) {
	for (let n = 0; n < stores.listingCap - 1; n++) {
		now += 1000;
		await login();
	}
	stores.down.closing.failNext("add");
	await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
	const kept = (await stores.listed.members("alice")) as readonly {
		member: string;
		remainingMs: number;
	}[];
	return kept.find(({ member }) => member === first);
}

it("puts a pushed-out session back for the whole lifetime when its record cannot be read", async () => {
	const booted = await boot();
	const { s, stores, login, withCookie } = booted;
	const first = ((await s.enter(withCookie(await login()))) as Session).id;
	await stores.kept.records.change(first, (r) => ({
		value: { ...(r as object), format: 3 } as unknown as StoredSession,
	}));
	expect((await pushOutRefused(booted, first))?.remainingMs).toBe(3_600_000);
});

it("does not put back a pushed-out session already closed", async () => {
	const booted = await boot();
	const { s, stores, login, withCookie } = booted;
	const first = ((await s.enter(withCookie(await login()))) as Session).id;
	stores.down.listed.failNext("remove");
	expect((await s.close(first)).kind).toBe("closed");
	expect(await pushOutRefused(booted, first)).toBeUndefined();
});

it("ends a pushed-out session it cannot put back, so none stays open and unlisted", async () => {
	const booted = await boot();
	const { s, stores, login, withCookie } = booted;
	const cookie = await login();
	const first = ((await s.enter(withCookie(cookie))) as Session).id;
	stores.down.sessions.failNext("read");
	expect(await pushOutRefused(booted, first)).toBeUndefined();
	expect(await s.enter(withCookie(cookie))).toBeUndefined();
});

it("puts a pushed-out session back though the opened one cannot be taken off", async () => {
	const booted = await boot();
	const { s, stores, login, withCookie } = booted;
	const first = ((await s.enter(withCookie(await login()))) as Session).id;
	stores.down.listed.failNext("remove");
	expect(await pushOutRefused(booted, first)).toBeDefined();
});

it("ends a session the put-back pushes out, so none is left open off the listing, and logs how many it ended", async () => {
	const { s, stores, login, withCookie, logged } = await boot();
	const first = ((await s.enter(withCookie(await login()))) as Session).id;
	const cookies: string[] = [];
	for (let n = 0; n < stores.listingCap - 1; n++) {
		now += 1000;
		cookies.push(await login());
	}
	// The opened session stays listed, so the listing is full again when the first is put back.
	stores.down.closing.failNext("add");
	stores.down.listed.failNext("remove");
	await expect(s.complete(testRequest(), facts())).rejects.toSatisfy(isUnavailable);
	const listed = (await stores.listed.members("alice")).map(({ member }) => member);
	expect(listed).toContain(first);
	// The second login's session, the one ending first after the first's, was pushed out and ended.
	expect(await s.enter(withCookie(cookies[0] as string))).toBeUndefined();
	expect(await s.enter(withCookie(cookies[1] as string))).toBeDefined();
	expect(logged("session-lifecycle.listing_ended")).toEqual([
		expect.objectContaining({ fields: { count: 1 } }),
	]);
});
