import {
	type Instance,
	instanceOf,
	type Match,
	ready,
	replicasOnline,
	repointed,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { type Answer, assertion, faultScene, grantAt, on, said } from "../../faults/test/faults.ts";
import { grantDecision, requestCounted } from "../../faults/test/wire.ts";

// The scene's value, not the area's (`open`, which the other fault scenes take to reach the grant):
// `closed` is the deployment's default, under which a request the limit cannot count is refused.
const scene = faultScene({ rateLimitWhileStoreFails: "closed" });

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
/**
 * The answer under the fault: the request limit's own (`service_unavailable`, not the grant's
 * `temporarily_unavailable`), with no token.
 */
const unavailable = [503, "service_unavailable"];
/** An answer at the moment it came. */
const grantedAt = async (i: Instance) => {
	const answer: Answer = await grantAt(i, assertion());
	return { ...answer, at: performance.now() };
};
const noToken = (answer: Answer) => {
	expect(said(answer)).toEqual(unavailable);
	expect(answer.body.access_token).toBeUndefined();
};

/** The control: with no fault, a request is counted once and given a token. */
async function control(i: Instance) {
	const before = successes(i, requestCounted).length;
	expect(said(await grantAt(i, assertion()))).toEqual([200, "Bearer"]);
	expect(successes(i, requestCounted).length).toBe(before + 1);
}

/**
 * Refused at its count, as its answer says: none of the grant's calls
 * was sent from the fault on, not even one sent then and answered after. The relay records what Redis
 * answered; where every connection is cut (`R`) or Redis is down (`C`), a call cut on its way would go
 * unrecorded, so there this rests on the per-source policy running before the handler.
 */
async function refusedAtCount(i: Instance, from: number) {
	await ready(i);
	for (const call of grantDecision)
		expect(i.relay.executions(call).filter((e) => e.at > from)).toEqual([]);
}

/** Healed: the instance is ready, and a new request is counted and given a token. */
async function healed(i: Instance) {
	await ready(i);
	await control(i);
}

describe("the token endpoint's request limit letting no request by while the store cannot count, its fail mode closed", () => {
	it("refuses a request while the network from the app to Redis is cut [guarantee-3-h] {fault:Pu}", async () => {
		await on({ name: "requests-unavailable-pu", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await grantedAt(i);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Nothing reached Redis while cut: the count it sent then is answered only once resumed.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await refusedAtCount(i, stalled);
			await healed(i);
		});
	});

	it("refuses a request while the network from Redis to the app is cut [guarantee-3-h] {fault:Pd}", async () => {
		await on({ name: "requests-unavailable-pd", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await grantedAt(i);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Its count reached Redis, which counted it before the endpoint gave up; the answer was held.
			expect(
				i.relay.executions(requestCounted).some((e) => e.at > stalled && e.at < answer.at),
			).toBe(true);
			expect(resumed).toBeGreaterThan(answer.at);
			await refusedAtCount(i, stalled);
			await healed(i);
		});
	});

	it("refuses a request while every connection to Redis is cut as it opens [guarantee-3-h] {fault:R}", async () => {
		await on({ name: "requests-unavailable-r", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await grantedAt(i).finally(() => clearInterval(cutting));
			noToken(answer);
			// Nothing reached Redis from the first cut to the answer.
			expect(i.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			await refusedAtCount(i, cut);
			await healed(i);
		});
	});

	it("refuses a request while Redis answers later than the command timeout [guarantee-3-h] {fault:L}", async () => {
		await on({ name: "requests-unavailable-l", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await grantedAt(i);
			i.relay.delay(0, "both");
			noToken(answer);
			// Its count was answered only after the endpoint had given up on it.
			await ready(i);
			const count = i.relay.executions(requestCounted).find((e) => e.at > delayed);
			expect(count?.at).toBeGreaterThan(answer.at);
			await refusedAtCount(i, delayed);
			await healed(i);
		});
	});

	it("refuses a request while Redis is too slow to run commands [guarantee-3-h] {fault:S}", async () => {
		await on({ name: "requests-unavailable-s", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the endpoint's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await grantedAt(i);
			noToken(answer);
			// The endpoint answered while Redis slept, before its count was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				i.relay.executions(requestCounted).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			await refusedAtCount(i, asking);
			await healed(i);
		});
	});

	it("refuses a request while the primary holds its writes for a promotion [guarantee-3-h] {fault:F}", async () => {
		await on({ name: "requests-unavailable-f", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof grantedAt>> | undefined;
			const from = performance.now();
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					answer = await grantedAt(i);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("no answer while the writes were held");
			noToken(answer);
			await refusedAtCount(i, from);
			await healed(i);
		});
	});

	it("refuses a request whose count Redis was killed under at once and started again [guarantee-3-h] {fault:C}", async () => {
		await on({ name: "requests-unavailable-c", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			// The count held, then Redis killed under it: the count goes with its connection.
			const from = performance.now();
			const holding = i.relay.hold(requestCounted);
			const asked = grantedAt(i);
			await holding;
			// Nothing reaches Redis until it is started again and the relay points at it.
			i.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			i.relay.resume();
			const answer = await asked;
			noToken(answer);
			// A count carries no mark to resend under: the held one was never sent, and none followed it,
			// so the server started again holds no count of it to let the request by on.
			expect(i.relay.executions(requestCounted).filter((e) => e.at > from)).toEqual([]);
			await replicasOnline(d);
			await refusedAtCount(i, from);
			await healed(i);
		});
	});
});
