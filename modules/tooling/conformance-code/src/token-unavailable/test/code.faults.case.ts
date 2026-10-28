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
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { type Answer, type Code, codeAt, on, redeemAt, said } from "../../faults/test/faults.ts";
import { codeRead, codeUse, isStoreOperation } from "../../faults/test/wire.ts";

// The area lets requests by uncounted where the store fails (rate-limit's fail-mode open), so each
// scene reaches the redemption's own decision: the read of the code's record, then its use.

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/** The answer under the fault: unavailable, with no token. */
const unavailable = [503, "temporarily_unavailable"];
/** A redemption's answer at the moment it came. */
const redeemedAt = async (i: Instance, c: Code) => {
	const answer: Answer = await redeemAt(i, c);
	return { ...answer, at: performance.now() };
};
const noToken = (answer: Answer) => {
	expect(said(answer)).toEqual(unavailable);
	expect(answer.body.access_token).toBeUndefined();
};

/** The control: with no fault, a code is used up by one write and a token is issued for it. */
async function control(i: Instance) {
	const c = await codeAt(i);
	expect(said(await redeemAt(i, c))).toEqual([200, "Bearer"]);
	expect(successes(i, codeUse(c))).toHaveLength(1);
}

/** Healed: the topology has recovered and the instance is ready, and a new code is redeemed. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	expect(said(await redeemAt(i, await codeAt(i)))).toEqual([200, "Bearer"]);
}

describe("the token endpoint issuing no token for a code while the store cannot answer", () => {
	it("gives no token while the network from the app to Redis is cut [guarantee-3-b] {fault:Pu}", async () => {
		await on({ name: "code-token-unavailable-pu" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await redeemedAt(i, c);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Nothing reached Redis while cut: what it sent then is answered only once resumed.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(i);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the network from Redis to the app is cut [guarantee-3-b] {fault:Pd}", async () => {
		await on({ name: "code-token-unavailable-pd" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await redeemedAt(i, c);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Its read of the code reached Redis, which answered it before the endpoint gave up; the answer was held.
			expect(i.relay.executions(codeRead).some((e) => e.at > stalled && e.at < answer.at)).toBe(
				true,
			);
			expect(resumed).toBeGreaterThan(answer.at);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while every connection to Redis is cut as it opens [guarantee-3-b] {fault:R}", async () => {
		await on({ name: "code-token-unavailable-r" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await redeemedAt(i, c).finally(() => clearInterval(cutting));
			noToken(answer);
			// Nothing reached Redis from the first cut to the answer.
			expect(i.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis answers later than the command timeout [guarantee-3-b] {fault:L}", async () => {
		await on({ name: "code-token-unavailable-l" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await redeemedAt(i, c);
			i.relay.delay(0, "both");
			noToken(answer);
			// Its read of the code was answered only after the endpoint had given up on it.
			await ready(i);
			const read = i.relay.executions(codeRead).find((e) => e.at > delayed);
			expect(read?.at).toBeGreaterThan(answer.at);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis is too slow to run commands [guarantee-3-b] {fault:S}", async () => {
		await on({ name: "code-token-unavailable-s" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the endpoint's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await redeemedAt(i, c);
			noToken(answer);
			// The endpoint answered while Redis slept, before any read of the code was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(i.relay.executions(codeRead).filter((e) => e.at > asking && e.at < answer.at)).toEqual(
				[],
			);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the primary holds its writes for a promotion [guarantee-3-b] {fault:F}", async () => {
		await on({ name: "code-token-unavailable-f" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof redeemedAt>> | undefined;
			let paused = 0;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					paused = performance.now();
					answer = await redeemedAt(i, c);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("no answer while the writes were held");
			noToken(answer);
			// Redis ran none of the redemption's calls while it held its writes: the code was not used.
			const held = answer.at;
			expect(
				i.relay
					.executions(anything)
					.filter((e) => isStoreOperation(e.command) && e.at > paused && e.at < held),
			).toEqual([]);
			expect(successes(i, codeUse(c))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token for a decision confirmed on a server other than the one that answered it [guarantee-3-b] {fault:Fs}", async () => {
		await on({ name: "code-token-unavailable-fs", replicas: 3 }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			i.relay.switchUpstream(moved.upstream());
			i.relay.reset("operations");
			// Sent once the app holds a connection to the new primary: before, it fails for want of one, a 503 that shows nothing.
			await reconnected(i, moved.upstream());
			const from = performance.now();
			const confirmed = i.relay.observe(confirmation({ replicas: 1 }));
			const answer = await redeemedAt(i, c);
			const wait = await confirmed;
			const upstreamOf = (id: number) => i.relay.connections().find((x) => x.id === id)?.upstream;
			// A call the decision made ran on the new primary, its confirmation passing on the old one.
			const first = i.relay
				.executions(anything)
				.filter(
					(e) =>
						e.at > from &&
						e.at < wait.at &&
						isStoreOperation(e.command) &&
						runIdOf(e.reply) !== undefined,
				)
				.at(-1);
			expect(first && runIdOf(first.reply)).toBe(newId);
			expect(first && upstreamOf(first.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			noToken(answer);
			i.relay.reset("confirming");
			await healed(d, i);
		});
	});

	it("gives no token from a decision made while Redis is killed at once and started again [guarantee-3-b] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "code-token-unavailable-c" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const c = await codeAt(i);
			// The code's use held, then Redis killed under it: the write goes with its connection.
			const from = performance.now();
			const holding = i.relay.hold(codeUse(c));
			const asked = redeemedAt(i, c);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// uses the code comes after.
			i.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			i.relay.resume();
			const answer = await asked;
			// Resent within its patience, the use may land on the server started again, which answers
			// it; a token is given only so. A resend whose confirmation failed takes the answer first
			// written, so the answers are counted, each the held write under its mark.
			const sent = i.relay.executions(codeUse(c)).filter((e) => e.at > from);
			const given = sent.filter((e) => e.succeeded);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.status === 200) {
				expect(given.length).toBeGreaterThan(0);
				expect(given.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("given a token for a use kept on Redis started again");
			} else {
				noToken(answer);
				await annotate("answered temporarily_unavailable");
			}
			await healed(d, i);
		});
	});
});
