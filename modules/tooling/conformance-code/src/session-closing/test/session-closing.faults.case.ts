import {
	confirmation,
	type Execution,
	type Instance,
	type Match,
	runIdOf,
	sameMark,
	storeWrite,
	writtenValues,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	browserOn,
	codeAt,
	failover,
	faultScene,
	instanceOf,
	on,
	prefix,
	ready,
	reconnected,
	redeemAt,
	replicasOnline,
	repointed,
} from "../../faults/test/faults.ts";
import { backChannel } from "../../testing.ts";

// Userinfo shows whether a token's path is open; pending closes are gone on with every second.
const scene = faultScene({ userinfo: true, sweepSeconds: 1 });
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const state = (v: unknown) => (v as { state?: unknown } | null)?.state;
/** A handle added to the closings: a shard's list holding one, as a scene starts with none pending. */
const added = storeWrite({
	prefix,
	space: "session-store.closings",
	value: (v) => Array.isArray(v) && v.length > 0,
});
/** The session's record written as `closing`, or as `closed`. */
const recordAs = (s: "closing" | "closed", handle?: string): Match =>
	storeWrite({
		prefix,
		space: "session-store.sessions",
		...(handle ? { partition: handle } : {}),
		value: (v) => state(v) === s,
	});
/** A participant's write: an access token of the session's put on the revoked list. */
const revocation = storeWrite({
	prefix,
	space: "tokens-store.revoked",
	operations: ["putIfAbsent"],
});
/** The closings' shard written without the handle: its close is done. */
const doneWith = (handle: string) =>
	storeWrite({
		prefix,
		space: "session-store.closings",
		value: (v) => Array.isArray(v) && !v.includes(handle),
	});

/** The handle the add wrote, the one item of its shard's list. */
function handleOf(add: Execution): string {
	const [list] = writtenValues(add.command).map((w) => w.value);
	if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== "string")
		throw new Error(`the closings held more than the one close: ${JSON.stringify(list)}`);
	return list[0];
}

/** A session opened at the instance, and an access token issued from it. */
async function sessionAt(i: Instance) {
	const browser = browserOn(i);
	const answer = await redeemAt(i, await codeAt(i, browser));
	const token = answer.body.access_token;
	if (typeof token !== "string") throw new Error(`no access token: ${answer.status}`);
	return { browser, token };
}

const userinfoAt = (i: Instance, token: string) =>
	fetch(`${i.baseUrl}/oauth/userinfo`, {
		headers: { ...backChannel, authorization: `Bearer ${token}` },
	}).then((r) => r.status);

const successesSince = (on: readonly Instance[], match: Match, since: number) =>
	on.flatMap((i) => i.relay.executions(match).filter((e) => e.succeeded && e.at > since));

/**
 * Until the close of `handle` is seen done on the instances' relays, within 30 s: a participant's
 * revocation after `since`, then the record written closed, then the closings without the handle,
 * in that order. A session left closing, never closed or never done, does not pass.
 */
async function closedAfter(on: readonly Instance[], handle: string, since: number) {
	const end = performance.now() + 30_000;
	for (;;) {
		const [revoked] = successesSince(on, revocation, since).sort((x, y) => x.at - y.at);
		const closed = revoked
			? successesSince(on, recordAs("closed", handle), revoked.at).sort((x, y) => x.at - y.at)[0]
			: undefined;
		const done = closed
			? successesSince(on, doneWith(handle), closed.at).sort((x, y) => x.at - y.at)[0]
			: undefined;
		if (revoked && closed && done) return { revoked, closed, done };
		if (performance.now() > end)
			throw new Error(
				`the close was not seen done: revoked ${!!revoked}, closed ${!!closed}, done ${!!done}`,
			);
		await pause(100);
	}
}

/**
 * The control: with no fault, a logout adds the close, writes the record closing, revokes the
 * session's token, writes it closed and is done, in that order, and the token is refused.
 */
async function control(i: Instance) {
	const s = await sessionAt(i);
	expect(await userinfoAt(i, s.token)).toBe(200);
	const from = performance.now();
	const add = i.relay.observe(added);
	expect(await s.browser.logout()).toBe(200);
	await closedAfter([i], handleOf(await add), from);
	expect(await userinfoAt(i, s.token)).toBe(401);
}

/** Which way a close stopped halfway was finished, for the scene's report: by the logout or a sweep. */
const finishedBy = (answer: number) =>
	answer === 200
		? "closed by the logout itself, its held write resent within its patience"
		: "closed by a sweep, the logout answering it pending";

/** After the fault: the old token is refused, and a new session's token is taken. */
async function refusedAfter(i: Instance, token: string) {
	expect(await userinfoAt(i, token)).toBe(401);
	expect(await userinfoAt(i, (await sessionAt(i)).token)).toBe(200);
}

/**
 * A logout at the instance whose close is confirmed closing and whose participant's write is held,
 * so the close stops halfway: its handle, the logout's answer to come, and when it began.
 */
async function heldHalfway(i: Instance) {
	const s = await sessionAt(i);
	const from = performance.now();
	const add = i.relay.observe(added);
	const closing = i.relay.observe(recordAs("closing"));
	const held = i.relay.hold(revocation);
	const answer = s.browser.logout().catch(() => 0);
	const handle = handleOf(await add);
	expect(writtenValues((await closing).command).map((w) => w.key.partition)).toEqual([handle]);
	return { ...s, handle, answer, from, held: await held };
}

describe("a closing session closed under faults", () => {
	it("closes a session whose closing's answer is lost once, the resend taking the first answer [guarantee-1-a] {fault:Lr}", async () => {
		await on({ name: "session-closing-lr", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const s = await sessionAt(a);
			const from = performance.now();
			const add = a.relay.observe(added);
			const drop = a.relay.dropReplyTo(recordAs("closing"));
			expect(await s.browser.logout()).toBe(200);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => x.command.name === "EVAL")).toEqual([]);
			const handle = handleOf(await add);
			const effects = successesSince([a], recordAs("closing", handle), from);
			expect(effects.length).toBeGreaterThan(1);
			expect(effects.every((e) => sameMark(dropped.command, e.command))).toBe(true);
			await closedAfter([a], handle, from);
			await refusedAfter(a, s.token);
		});
	});

	it("answers a logout unavailable when every answer to its closing is lost, another instance's sweep closing it [guarantee-1-a] {fault:Lx}", async () => {
		await on({ name: "session-closing-lx", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const s = await sessionAt(a);
			const from = performance.now();
			const add = a.relay.observe(added);
			const drop = a.relay.dropReplyTo(recordAs("closing"), { resends: sameMark });
			expect(await s.browser.logout()).toBe(503);
			await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			const handle = handleOf(await add);
			// The closings held it, so a sweep closes it; only the one logout was sent, to the first.
			await closedAfter([a, b], handle, from);
			expect(b.requests().filter((r) => r.path === "/session/logout")).toEqual([]);
			await ready(a);
			expect(await userinfoAt(b, s.token)).toBe(401);
			await refusedAfter(a, s.token);
		});
	});

	it("closes a session confirmed closing before a caught-up replica is promoted [guarantee-1-a] {fault:F}", async ({
		annotate,
	}) => {
		await on({ name: "session-closing-f", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const s = await heldHalfway(a);
			// The held write goes with its connection, unsent; resent within its patience it may land on
			// the new primary, the logout then closing it, or the logout answers it pending.
			await failover(d);
			const promoted = performance.now();
			const answer = await s.answer;
			expect([200, 503]).toContain(answer);
			await annotate(finishedBy(answer));
			await ready(a);
			await closedAfter([a], s.handle, promoted);
			await refusedAfter(a, s.token);
		});
	});

	it("never closes a session on a confirmation from a server other than the one that answered, and closes it once healed [guarantee-1-a] {fault:Fs}", async () => {
		await on({ name: "session-closing-fs", scene, replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const s = await heldHalfway(a);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			a.relay.switchUpstream(moved.upstream());
			a.relay.reset("operations");
			expect(await s.answer).not.toBe(200);
			// Watched once the app holds a connection to the new primary: before, its sweep fails for want of one.
			await reconnected(a, moved.upstream());
			const wait = await a.relay.observe(confirmation({ replicas: 1 }));
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			const sent = a.relay.executions(anything).filter((e) => e.at > s.from);
			// The sweep's calls run on the new primary, on a connection to it, and their confirmation
			// passes on the old one, on a connection still to it ...
			// The write it confirms may have been resent on the new connection as it opened, before the
			// relay was watched, so it is looked for from the logout's start.
			const first = a.relay
				.executions(anything)
				.filter(
					(e) =>
						e.at > s.from &&
						e.at < wait.at &&
						e.command.name === "EVAL" &&
						runIdOf(e.reply) !== undefined,
				)
				.at(-1);
			expect(first && runIdOf(first.reply)).toBe(newId);
			expect(first && upstreamOf(first.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			const info = sent.findLast(
				(e) => e.connection === wait.connection && e.command.name === "INFO",
			);
			expect(info?.reply.kind === "bulk" && info.reply.data?.toString()).toContain(
				`run_id:${oldId}`,
			);
			// ... so the comparison of the two run ids alone keeps the close from going on.
			await pause(2_000);
			expect(successesSince([a], recordAs("closed", s.handle), s.from)).toEqual([]);
			a.relay.reset("confirming");
			const healed = performance.now();
			await ready(a);
			const { closed } = await closedAfter([a], s.handle, s.from);
			expect(closed.at).toBeGreaterThan(healed);
			await refusedAfter(a, s.token);
		});
	});

	it("closes a session confirmed closing before Redis is killed at once and started again [guarantee-1-a] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "session-closing-c", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const s = await heldHalfway(a);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const restarted = performance.now();
			repointed(d);
			await replicasOnline(d);
			const answer = await s.answer;
			expect([200, 503]).toContain(answer);
			await annotate(finishedBy(answer));
			await ready(a);
			await closedAfter([a], s.handle, restarted);
			await refusedAfter(a, s.token);
		});
	});

	it("closes, at another instance's sweep, a session whose instance was killed halfway through closing it [guarantee-1-a] {fault:K}", async () => {
		await on({ name: "session-closing-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const s = await heldHalfway(a);
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			// Meanwhile the session is closing, which lets no token in.
			expect(await userinfoAt(b, s.token)).toBe(401);
			await closedAfter([b], s.handle, ended.endedAt);
			// The held write was never sent, and only the one logout was, to the killed instance.
			expect(successesSince([a], revocation, s.from)).toEqual([]);
			expect(b.requests().filter((r) => r.path === "/session/logout")).toEqual([]);
			await refusedAfter(b, s.token);
		});
	});

	it("closes a session once whose close another instance's sweep goes on with at the same time [guarantee-1-a] {fault:H2}", async () => {
		await on({ name: "session-closing-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const s = await heldHalfway(a);
			// The other's sweep closes it while the logout is held ...
			await closedAfter([b], s.handle, s.from);
			// ... and the logout, let go, finds it closed and answers so.
			s.held.release();
			expect(await s.answer).toBe(200);
			expect(await userinfoAt(a, s.token)).toBe(401);
			await refusedAfter(b, s.token);
		});
	});
});
