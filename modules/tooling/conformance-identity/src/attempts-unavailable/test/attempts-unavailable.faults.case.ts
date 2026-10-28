import {
	confirmation,
	type Deployed,
	type Instance,
	instanceOf,
	type Match,
	ready,
	reconnected,
	recovered,
	replicasOnline,
	repointed,
	runIdOf,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	type Answer,
	attemptFrom,
	faultScene,
	identifierLockout,
	loginAt,
	nextSource,
	on,
	said,
} from "../../faults/test/faults.ts";

// The scene's value, not the default (`closed`): a request limit lets requests by where the store
// cannot count, and the attempt limit refuses them still, whatever the fail mode.
const scene = faultScene({ rateLimitWhileStoreFails: "open" });
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/**
 * The answer under the fault: the attempt refused as its count could not be confirmed, whether or not
 * Redis counted it (`service_unavailable`, not the `temporarily_unavailable` of a session that could
 * not open), and no session.
 */
const refusedUnconfirmed = [503, "service_unavailable", false];

/** The control: with no fault, a login's attempt is counted once, and it opens a session. */
async function control(i: Instance) {
	const source = nextSource();
	expect(said(await loginAt(i, source))).toEqual([200, undefined, true]);
	expect(successes(i, attemptFrom(source))).toHaveLength(1);
}

/**
 * Refused at the attempt's count, so its identifier was never asked of: its lockout, which would answer
 * alike, saw no request from the fault on, not even one sent then and answered after. The relay records
 * what Redis answered; where every connection is cut (`R`) or Redis is down (`C`), a lockout request
 * cut on its way would go unrecorded, so there this rests on the per-source policy running before the
 * handler. Either way no attempt passes: the lockout is an attempt limit too, and refuses alike.
 */
async function refusedAtCount(i: Instance, from: number) {
	await ready(i);
	expect(i.relay.executions(identifierLockout).filter((e) => e.at > from)).toEqual([]);
}

/** Healed: the topology has recovered and the instance is ready, and a login from a new source is counted and opens a session. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	const source = nextSource();
	expect(said(await loginAt(i, source))).toEqual([200, undefined, true]);
	expect(successes(i, attemptFrom(source))).toHaveLength(1);
}

describe("password login's attempt limit letting no attempt by while the store cannot count", () => {
	it("refuses an attempt while the network from the app to Redis is cut [guarantee-3-i] {fault:Pu}", async () => {
		await on({ name: "attempts-unavailable-pu", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const stalled = performance.now();
			a.relay.stall("up");
			const answer = await loginAt(a, source);
			const resumed = performance.now();
			a.relay.resume();
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// Nothing reached Redis while cut: the count it sent then is answered only once resumed.
			expect(a.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(a);
			expect(a.relay.executions(attemptFrom(source)).some((e) => e.at > resumed)).toBe(true);
			await refusedAtCount(a, stalled);
			await healed(d, a);
		});
	});

	it("refuses an attempt while the network from Redis to the app is cut [guarantee-3-i] {fault:Pd}", async () => {
		await on({ name: "attempts-unavailable-pd", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const stalled = performance.now();
			a.relay.stall("down");
			const answer = await loginAt(a, source);
			a.relay.resume();
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// Its count reached Redis, which counted it before the login gave up; the answer was held.
			expect(
				a.relay.executions(attemptFrom(source)).some((e) => e.at > stalled && e.at < answer.at),
			).toBe(true);
			await refusedAtCount(a, stalled);
			await healed(d, a);
		});
	});

	it("refuses an attempt while every connection to Redis is cut as it opens [guarantee-3-i] {fault:R}", async () => {
		await on({ name: "attempts-unavailable-r", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const cut = performance.now();
			a.relay.reset("all");
			const cutting = setInterval(() => a.relay.reset("all"), 20);
			const answer = await loginAt(a, source).finally(() => clearInterval(cutting));
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// The attempt's count did not succeed from the first cut to the answer. Cuts 20 ms apart cannot
			// stop a command getting through on a connection just opened, so the scene checks only the
			// write its guarantee rests on.
			expect(
				successes(a, attemptFrom(source)).filter((e) => e.at > cut && e.at < answer.at),
			).toEqual([]);
			await refusedAtCount(a, cut);
			await healed(d, a);
		});
	});

	it("refuses an attempt while Redis answers later than the command timeout [guarantee-3-i] {fault:L}", async () => {
		await on({ name: "attempts-unavailable-l", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			a.relay.delay(1_500, "both");
			const answer = await loginAt(a, source);
			a.relay.delay(0, "both");
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// Its count was answered only after the login had given up on it.
			await ready(a);
			const count = a.relay.executions(attemptFrom(source)).find((e) => e.at > delayed);
			expect(count?.at).toBeGreaterThan(answer.at);
			await refusedAtCount(a, delayed);
			await healed(d, a);
		});
	});

	it("refuses an attempt while Redis is too slow to run commands [guarantee-3-i] {fault:S}", async () => {
		await on({ name: "attempts-unavailable-s", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the login's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await loginAt(a, source);
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// The login answered while Redis slept, before its count was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				a.relay.executions(attemptFrom(source)).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			await refusedAtCount(a, asking);
			await healed(d, a);
		});
	});

	it("refuses an attempt while the primary holds its writes for a promotion [guarantee-3-i] {fault:F}", async () => {
		await on({ name: "attempts-unavailable-f", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Answer | undefined;
			const from = performance.now();
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					answer = await loginAt(a, source);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("the login was not answered during the promotion");
			expect(said(answer)).toEqual(refusedUnconfirmed);
			await refusedAtCount(a, from);
			await healed(d, a);
		});
	});

	it("refuses an attempt counted on a server other than the one that confirmed it [guarantee-3-i] {fault:Fs}", async () => {
		await on({ name: "attempts-unavailable-fs", scene, replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			a.relay.switchUpstream(moved.upstream());
			a.relay.reset("operations");
			// Sent once the app holds a connection to the new primary: before, it fails for want of one, a 503 that shows nothing.
			await reconnected(a, moved.upstream());
			const from = performance.now();
			const confirmed = a.relay.observe(confirmation({ replicas: 1 }));
			const answer = await loginAt(a, source);
			const wait = await confirmed;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			// The count ran on the new primary, its confirmation passing on the old one.
			const count = a.relay
				.executions(attemptFrom(source))
				.filter((e) => e.at > from && e.at < wait.at)
				.at(-1);
			expect(count && runIdOf(count.reply)).toBe(newId);
			expect(count && upstreamOf(count.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			expect(said(answer)).toEqual(refusedUnconfirmed);
			a.relay.reset("confirming");
			await refusedAtCount(a, from);
			await healed(d, a);
		});
	});

	it("refuses an attempt whose count Redis was killed under at once and started again [guarantee-3-i] {fault:C}", async () => {
		await on({ name: "attempts-unavailable-c", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const source = nextSource();
			// The count held, then Redis killed under it: the count goes with its connection.
			const from = performance.now();
			const holding = a.relay.hold(attemptFrom(source));
			const asked = loginAt(a, source);
			await holding;
			// Nothing reaches Redis until it is started again and the relay points at it.
			a.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			a.relay.resume();
			const answer = await asked;
			expect(said(answer)).toEqual(refusedUnconfirmed);
			// A count carries no mark to resend under: the held one was never sent, and none followed it.
			expect(a.relay.executions(attemptFrom(source)).filter((e) => e.at > from)).toEqual([]);
			await replicasOnline(d);
			await refusedAtCount(a, from);
			await healed(d, a);
		});
	});
});
