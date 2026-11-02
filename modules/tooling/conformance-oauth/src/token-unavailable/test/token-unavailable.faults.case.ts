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
	storeRead,
	storeWrite,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	type Answer,
	assertion,
	grantAt,
	on,
	prefix,
	said,
	spendOf,
} from "../../faults/test/faults.ts";

// The area lets requests by uncounted where the store fails (rate-limit's fail-mode open), so each
// scene reaches the grant's own decision: the subject's revocation boundary read, then the spend.

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
/** Any assertion's spend, as the grant writes it. */
const spent = storeWrite({ prefix, space: "jwt-bearer-store.spent", operations: ["putIfAbsent"] });
/** The read of the subject's revocation boundary, which the decision waits on before the spend. */
const boundaryRead = storeRead({ prefix, space: "subject-revocation-store.boundaries" });

/** The answer under the fault: unavailable, with no token. */
const unavailable = [503, "temporarily_unavailable"];
/** An answer at the moment it came. */
const grantedAt = async (i: Instance, a = assertion()) => {
	const answer: Answer = await grantAt(i, a);
	return { ...answer, at: performance.now() };
};
const noToken = (answer: Answer) => {
	expect(said(answer)).toEqual(unavailable);
	expect(answer.body.access_token).toBeUndefined();
};

/** The control: with no fault, the grant spends one assertion and gives a token. */
async function control(i: Instance) {
	const before = successes(i, spent).length;
	expect(said(await grantAt(i, assertion()))).toEqual([200, "Bearer"]);
	expect(successes(i, spent).length).toBe(before + 1);
}

/** Healed: the topology has recovered and the instance is ready, and a new assertion is given a token. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	expect(said(await grantAt(i, assertion()))).toEqual([200, "Bearer"]);
}

describe("the token endpoint issuing no token for a JWT bearer assertion while the store cannot answer", () => {
	it("gives no token while the network from the app to Redis is cut [guarantee-3-d] {fault:Pu}", async () => {
		await on({ name: "token-unavailable-pu" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await grantedAt(i, a);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Nothing reached Redis while cut: what it sent then is answered only once resumed.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(i);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the network from Redis to the app is cut [guarantee-3-d] {fault:Pd}", async () => {
		await on({ name: "token-unavailable-pd" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await grantedAt(i, a);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Its boundary read reached Redis, which answered it before the endpoint gave up; the answer was held.
			expect(i.relay.executions(boundaryRead).some((e) => e.at > stalled && e.at < answer.at)).toBe(
				true,
			);
			expect(resumed).toBeGreaterThan(answer.at);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while every connection to Redis is cut as it opens [guarantee-3-d] {fault:R}", async () => {
		await on({ name: "token-unavailable-r" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await grantedAt(i, a).finally(() => clearInterval(cutting));
			noToken(answer);
			// Nothing reached Redis from the first cut to the answer.
			expect(i.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis answers later than the command timeout [guarantee-3-d] {fault:L}", async () => {
		await on({ name: "token-unavailable-l" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await grantedAt(i, a);
			i.relay.delay(0, "both");
			noToken(answer);
			// Its boundary read was answered only after the endpoint had given up on it.
			await ready(i);
			const read = i.relay.executions(boundaryRead).find((e) => e.at > delayed);
			expect(read?.at).toBeGreaterThan(answer.at);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis is too slow to run commands [guarantee-3-d] {fault:S}", async () => {
		await on({ name: "token-unavailable-s" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the endpoint's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await grantedAt(i, a);
			noToken(answer);
			// The endpoint answered while Redis slept, before any boundary read of it was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				i.relay.executions(boundaryRead).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the primary holds its writes for a promotion [guarantee-3-d] {fault:F}", async () => {
		await on({ name: "token-unavailable-f" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer:
				| { readonly status: number; readonly body: Answer["body"]; readonly at: number }
				| undefined;
			let paused = 0;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					paused = performance.now();
					answer = await grantedAt(i, a);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("no answer while the writes were held");
			noToken(answer);
			// Redis ran none of the grant's calls while it held its writes: the decision gave up before the spend.
			const held = answer.at;
			expect(
				i.relay
					.executions(anything)
					.filter((e) => e.command.name === "EVAL" && e.at > paused && e.at < held),
			).toEqual([]);
			expect(successes(i, spendOf(a))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token spent on a server other than the one that confirmed it [guarantee-3-d] {fault:Fs}", async () => {
		await on({ name: "token-unavailable-fs", replicas: 3 }, async (d) => {
			const i = instanceOf(d);
			await control(i);
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
			const a = assertion();
			const from = performance.now();
			const confirmed = i.relay.observe(confirmation({ replicas: 1 }));
			const answer = await grantedAt(i, a);
			const wait = await confirmed;
			const upstreamOf = (id: number) => i.relay.connections().find((x) => x.id === id)?.upstream;
			// The spend ran on the new primary, its confirmation passing on the old one.
			const spend = i.relay
				.executions(spendOf(a))
				.filter((e) => e.at > from && e.at < wait.at && runIdOf(e.reply) !== undefined)
				.at(-1);
			expect(spend && runIdOf(spend.reply)).toBe(newId);
			expect(spend && upstreamOf(spend.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			noToken(answer);
			i.relay.reset("confirming");
			await healed(d, i);
		});
	});

	it("gives no token from a decision made while Redis is killed at once and started again [guarantee-3-d] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "token-unavailable-c" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = assertion();
			// The spend held, then Redis killed under it: the write goes with its connection.
			const from = performance.now();
			const holding = i.relay.hold(spendOf(a));
			const asked = grantedAt(i, a);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// spends the assertion comes after.
			i.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			i.relay.resume();
			const answer = await asked;
			// Resent within its patience, the spend may land on the server started again, which
			// answers it; a token is given only so. A resend whose confirmation failed takes the answer
			// first written, so the answers are counted, each the held write under its mark.
			const sent = i.relay.executions(spendOf(a)).filter((e) => e.at > from);
			const given = sent.filter((e) => e.succeeded);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.status === 200) {
				expect(given.length).toBeGreaterThan(0);
				expect(given.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("given a token for a spend kept on Redis started again");
			} else {
				noToken(answer);
				await annotate("answered temporarily_unavailable");
			}
			await replicasOnline(d);
			await healed(d, i);
		});
	});
});
