import {
	confirmation,
	failover,
	type Instance,
	instanceOf,
	type Match,
	ready,
	reconnected,
	replicasOnline,
	repointed,
	runIdOf,
	sameMark,
	writtenValues,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { browserOn, codeAt, faultScene, on, redeemAt } from "../../faults/test/faults.ts";
import {
	added,
	type Closing,
	closingOf,
	doneWith,
	isStoreOperation,
	recordAs,
	revocationOf,
} from "../../faults/test/wire.ts";
import { backChannel } from "../../testing.ts";

// Userinfo shows whether a token's path is open; pending closes are gone on with every second. The
// scene's values, not the defaults. A sweep reads every shard of the closings in turn, each read confirmed.
// closing-shards 4: over the default 1024, one sweep on CI's round trips runs past the scene's 30 s wait.
const scene = faultScene({ userinfo: true, sweepSeconds: 1, closingShards: 4 });
// sweep-interval 3600: the logout alone closes it, so no sweep of its own writes closing under another mark.
const logoutAlone = faultScene({ userinfo: true, sweepSeconds: 3600 });
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The `jti` of an access token issued as a JWT. */
const jtiOf = (token: string) => {
	const claims = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());
	if (typeof claims.jti !== "string") throw new Error("the access token names no jti");
	return claims.jti as string;
};

/** A session opened at the instance, and an access token issued from it. */
async function sessionAt(i: Instance) {
	const browser = browserOn(i);
	const answer = await redeemAt(i, await codeAt(i, browser));
	const token = answer.body.access_token;
	if (typeof token !== "string") throw new Error(`no access token: ${answer.status}`);
	return { browser, token, jti: jtiOf(token) };
}

const userinfoAt = (i: Instance, token: string) =>
	fetch(`${i.baseUrl}/oauth/userinfo`, {
		headers: { ...backChannel, authorization: `Bearer ${token}` },
	}).then((r) => r.status);

const successesSince = (on: readonly Instance[], match: Match, since: number) =>
	on.flatMap((i) => i.relay.executions(match).filter((e) => e.succeeded && e.at > since));

/**
 * Until the close is seen done on the instances' relays, within 30 s: its token's revocation after
 * `since`, then its record written closed, then its shard without its handle, in that order. A
 * session left closing, never closed or never done, does not pass.
 */
async function closedAfter(on: readonly Instance[], c: Closing, since: number) {
	const end = performance.now() + 30_000;
	const first = (match: Match, after: number) =>
		successesSince(on, match, after).sort((x, y) => x.at - y.at)[0];
	for (;;) {
		const revoked = first(revocationOf(c.jti), since);
		const closed = revoked && first(recordAs("closed", c.handle), revoked.at);
		const done = closed && first(doneWith(c), closed.at);
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
	await closedAfter([i], closingOf(await add, s.jti), from);
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
 * so the close stops halfway: its handle, the logout's answer to come and when it comes, and when it began.
 */
async function heldHalfway(i: Instance) {
	const s = await sessionAt(i);
	const from = performance.now();
	const add = i.relay.observe(added);
	const closing = i.relay.observe(recordAs("closing"));
	const held = i.relay.hold(revocationOf(s.jti));
	const answer = s.browser.logout().catch(() => 0);
	const answered = answer.then(() => performance.now());
	const c = closingOf(await add, s.jti);
	expect(writtenValues((await closing).command).map((w) => w.key.partition)).toEqual([c.handle]);
	return { ...s, closing: c, answer, answered, from, held: await held };
}

/**
 * The close stopped halfway seen done after the fault, from `since`. A logout answered done was done
 * before its answer: its revocation, its record closed and its shard done each seen on the relay
 * first. One answered pending is finished later, by a sweep.
 */
async function finishedAfter(
	i: Instance,
	s: Awaited<ReturnType<typeof heldHalfway>>,
	answer: number,
	since: number,
) {
	const seen = await closedAfter([i], s.closing, since);
	if (answer !== 200) return;
	const answered = await s.answered;
	for (const step of [seen.revoked, seen.closed, seen.done]) expect(step.at).toBeLessThan(answered);
}

describe("a closing session closed under faults", () => {
	it("closes a session whose closing's answer is lost once, the resend taking the first answer [guarantee-1-a] {fault:Lr}", async () => {
		await on({ name: "session-closing-lr", scene: logoutAlone }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const s = await sessionAt(a);
			const from = performance.now();
			const add = a.relay.observe(added);
			const drop = a.relay.dropReplyTo(recordAs("closing"));
			expect(await s.browser.logout()).toBe(200);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => isStoreOperation(x.command))).toEqual([]);
			const c = closingOf(await add, s.jti);
			const effects = successesSince([a], recordAs("closing", c.handle), from);
			expect(effects.length).toBeGreaterThan(1);
			expect(effects.every((e) => sameMark(dropped.command, e.command))).toBe(true);
			await closedAfter([a], c, from);
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
			const c = closingOf(await add, s.jti);
			// The closings held it, so a sweep closes it; only the one logout was sent, to the first.
			await closedAfter([a, b], c, from);
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
			// the new primary, the logout then closing it, or the logout answers it pending. Nothing
			// reaches Redis until the promotion is done, so all that closes it comes after.
			a.relay.stall("up");
			await failover(d);
			const promoted = performance.now();
			a.relay.resume();
			const answer = await s.answer;
			expect([200, 503]).toContain(answer);
			await annotate(finishedBy(answer));
			await ready(a);
			await finishedAfter(a, s, answer, promoted);
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
						isStoreOperation(e.command) &&
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
			expect(successesSince([a], recordAs("closed", s.closing.handle), s.from)).toEqual([]);
			a.relay.reset("confirming");
			const healed = performance.now();
			await ready(a);
			const { closed } = await closedAfter([a], s.closing, s.from);
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
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// closes it comes after.
			a.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			const restarted = performance.now();
			a.relay.resume();
			const answer = await s.answer;
			expect([200, 503]).toContain(answer);
			await annotate(finishedBy(answer));
			await ready(a);
			await finishedAfter(a, s, answer, restarted);
			await refusedAfter(a, s.token);
		});
	});

	it("closes, at another instance's sweep, a session whose instance was killed halfway through closing it [guarantee-1-a] {fault:K}", async () => {
		await on({ name: "session-closing-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			// The other's sweep reaches nothing until the first is killed, so it closes only after.
			b.relay.stall("up");
			const s = await heldHalfway(a);
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			b.relay.resume();
			// The session is closing, then closed, either of which lets no token in.
			expect(await userinfoAt(b, s.token)).toBe(401);
			await closedAfter([b], s.closing, ended.endedAt);
			// The held write was never sent, and only the one logout was, to the killed instance.
			expect(successesSince([a], revocationOf(s.jti), s.from)).toEqual([]);
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
			await closedAfter([b], s.closing, s.from);
			// ... and the logout, let go, finds it closed and answers so.
			s.held.release();
			expect(await s.answer).toBe(200);
			expect(await userinfoAt(a, s.token)).toBe(401);
			await refusedAfter(b, s.token);
		});
	});
});
