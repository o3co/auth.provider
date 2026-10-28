import {
	confirmation,
	type Instance,
	instanceOf,
	type Match,
	ready,
	reconnected,
	replicasOnline,
	repointed,
	runIdOf,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	type Answer,
	attemptFrom,
	cookieIndexed,
	loginAt,
	nextSource,
	on,
	said,
	sessionRecord,
} from "../../faults/test/faults.ts";

// Each fault comes once the attempt is counted and the login holds its first session write: earlier,
// the attempt limit refuses first (attempts-unavailable's scenes), and the session is never reached.

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/**
 * The answer under the fault: the session could not be opened (`temporarily_unavailable`, not the
 * `service_unavailable` of an attempt not counted), and no session.
 */
const unopened = [503, "temporarily_unavailable", false];

/** The control: with no fault, a login writes its session's record and its cookie's index, and opens it. */
async function control(i: Instance) {
	const from = performance.now();
	expect(said(await loginAt(i, nextSource()))).toEqual([200, undefined, true]);
	expect(successes(i, sessionRecord).filter((e) => e.at > from).length).toBeGreaterThan(0);
	expect(successes(i, cookieIndexed).filter((e) => e.at > from).length).toBeGreaterThan(0);
}

/** A login held at its session's record, its attempt counted once: the fault comes after the limit. */
async function heldAtSession(i: Instance) {
	const source = nextSource();
	const holding = i.relay.hold(sessionRecord);
	const asked = loginAt(i, source);
	const held = await holding;
	expect(successes(i, attemptFrom(source))).toHaveLength(1);
	return { held, asked };
}

/**
 * No session opened: from the fault on, no session was indexed under a cookie, not even by a write
 * sent then and answered after, so no request can reach a session the login began.
 */
async function noSessionOpened(i: Instance, from: number) {
	await ready(i);
	expect(successes(i, cookieIndexed).filter((e) => e.at > from)).toEqual([]);
}

/** Healed: the instance is ready, and a new login opens a session. */
async function healed(i: Instance) {
	await ready(i);
	expect(said(await loginAt(i, nextSource()))).toEqual([200, undefined, true]);
}

describe("password login opening no session while the store cannot answer", () => {
	it("opens no session while the network from the app to Redis is cut [guarantee-3-f] {fault:Pu}", async () => {
		await on({ name: "login-unavailable-pu" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			const stalled = performance.now();
			a.relay.stall("up");
			held.release();
			const answer = await asked;
			const resumed = performance.now();
			a.relay.resume();
			expect(said(answer)).toEqual(unopened);
			// Nothing reached Redis while cut: the record it sent then is answered only once resumed.
			expect(a.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(a);
			expect(a.relay.executions(sessionRecord).some((e) => e.at > resumed)).toBe(true);
			await noSessionOpened(a, stalled);
			await healed(a);
		});
	});

	it("opens no session while the network from Redis to the app is cut [guarantee-3-f] {fault:Pd}", async () => {
		await on({ name: "login-unavailable-pd" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			const stalled = performance.now();
			a.relay.stall("down");
			held.release();
			const answer = await asked;
			a.relay.resume();
			expect(said(answer)).toEqual(unopened);
			// Its record reached Redis, which wrote it before the login gave up; the answer was held.
			expect(
				a.relay.executions(sessionRecord).some((e) => e.at > stalled && e.at < answer.at),
			).toBe(true);
			await noSessionOpened(a, stalled);
			await healed(a);
		});
	});

	it("opens no session while every connection to Redis is cut as it opens [guarantee-3-f] {fault:R}", async () => {
		await on({ name: "login-unavailable-r" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			const cut = performance.now();
			// The held record goes with its connection.
			a.relay.reset("all");
			const cutting = setInterval(() => a.relay.reset("all"), 20);
			held.release();
			const answer = await asked.finally(() => clearInterval(cutting));
			expect(said(answer)).toEqual(unopened);
			// No session was indexed under a cookie from the first cut to the answer: the index is the write
			// that makes a session reachable. Cuts 20 ms apart cannot stop a command getting through on a
			// connection just opened, and records' resend of the record may land so and write it; the
			// record alone opens no session.
			expect(successes(a, cookieIndexed).filter((e) => e.at > cut && e.at < answer.at)).toEqual([]);
			await noSessionOpened(a, cut);
			await healed(a);
		});
	});

	it("opens no session while Redis answers later than the command timeout [guarantee-3-f] {fault:L}", async () => {
		await on({ name: "login-unavailable-l" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			// Past the command timeout (1 s by default) each way.
			a.relay.delay(1_500, "both");
			const released = performance.now();
			held.release();
			const answer = await asked;
			a.relay.delay(0, "both");
			expect(said(answer)).toEqual(unopened);
			// Its record reached Redis only past the command timeout, so no answer to it came in time.
			const first = a.relay.executions(sessionRecord).find((e) => e.at > released);
			expect(first?.at).toBeGreaterThan(released + 1_000);
			await noSessionOpened(a, released);
			await healed(a);
		});
	});

	it("opens no session while Redis is too slow to run commands [guarantee-3-f] {fault:S}", async () => {
		await on({ name: "login-unavailable-s" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			// The scene's value: the record is resent for about 25 s before the login gives up, so Redis
			// sleeps past the login's answer, and the answer is the slowness's, not a late write's refusal.
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 40);
			// When Redis woke, taken as it wakes, apart from the login's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const released = performance.now();
			held.release();
			const answer = await asked;
			expect(said(answer)).toEqual(unopened);
			// The login answered while Redis slept, before its record was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				a.relay.executions(sessionRecord).filter((e) => e.at > released && e.at < answer.at),
			).toEqual([]);
			await noSessionOpened(a, released);
			await healed(a);
		});
	});

	it("opens no session while the primary holds its writes for a promotion [guarantee-3-f] {fault:F}", async () => {
		await on({ name: "login-unavailable-f" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Answer | undefined;
			const from = performance.now();
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					held.release();
					answer = await asked;
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("the login was not answered during the promotion");
			expect(said(answer)).toEqual(unopened);
			const at = answer.at;
			expect(successes(a, sessionRecord).filter((e) => e.at > from && e.at < at)).toEqual([]);
			await noSessionOpened(a, from);
			await healed(a);
		});
	});

	it("opens no session whose record is written on a server other than the one that confirmed it [guarantee-3-f] {fault:Fs}", async () => {
		await on({ name: "login-unavailable-fs", replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			// Two primaries first, the app still on the old one for both its connections, so the attempt is
			// counted and confirmed on one server.
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			const { asked } = await heldAtSession(a);
			// The held record goes with its connection; resent, it is written on the new primary.
			a.relay.switchUpstream(moved.upstream());
			const from = performance.now();
			a.relay.reset("operations");
			await reconnected(a, moved.upstream());
			const confirmed = a.relay.observe(confirmation({ replicas: 1 }));
			const wait = await confirmed;
			const answer = await asked;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			// The record ran on the new primary, its confirmation passing on the old one.
			const record = a.relay
				.executions(sessionRecord)
				.filter((e) => e.at > from && e.at < wait.at)
				.at(-1);
			expect(record && runIdOf(record.reply)).toBe(newId);
			expect(record && upstreamOf(record.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			expect(said(answer)).toEqual(unopened);
			a.relay.reset("confirming");
			await noSessionOpened(a, from);
			await healed(a);
		});
	});

	it("opens a session from a login made while Redis is killed at once and started again only where the server started again keeps it [guarantee-3-f] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "login-unavailable-c" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtSession(a);
			const from = performance.now();
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// opens the session comes after.
			a.relay.stall("up");
			// The held record goes with its connection.
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			held.release();
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			a.relay.resume();
			const answer = await asked;
			// Resent within its patience under its mark, the record may land on the server started again,
			// which answers it; a session is opened only so, and indexed there too.
			const sent = a.relay.executions(sessionRecord).filter((e) => e.at > from);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.session) {
				expect(said(answer)).toEqual([200, undefined, true]);
				// Its record and its index each kept, every one after the restart, on the server started again.
				const indexed = a.relay.executions(cookieIndexed).filter((e) => e.at > from);
				for (const writes of [sent, indexed]) {
					const kept = writes.filter((e) => e.succeeded);
					expect(kept.length).toBeGreaterThan(0);
					expect(kept.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				}
				await annotate("opened a session kept on Redis started again");
			} else {
				expect(said(answer)).toEqual(unopened);
				await noSessionOpened(a, from);
				await annotate("answered temporarily_unavailable");
			}
			await replicasOnline(d);
			await healed(a);
		});
	});
});
