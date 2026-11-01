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
import {
	type Answer,
	approvedAt,
	type Device,
	on,
	pollAt,
	said,
} from "../../faults/test/faults.ts";
import { isStoreCall, recordReadOf, sessionEntryRead, takeOf } from "../../faults/test/wire.ts";

// The area lets requests go uncounted where the store fails (rate-limit's fail-mode open, as the OAuth
// part sets it), so each scene reaches the device grant's own decision: the device's record, the
// approving session's entry, then the take of the approval.

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
/** Every store operation; not a connection's handshake nor the confirming connection's rounds. */
const operations: Match = { request: isStoreCall, succeeded: () => true };

/** A poll's answer at the moment it came. */
const polledAt = async (i: Instance, d: Device) => {
	const answer: Answer = await pollAt(i, d);
	return { ...answer, at: performance.now() };
};
/** The answer under the fault: unavailable, with no token. */
const noToken = (answer: Answer) => {
	expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
	expect(answer.body.access_token).toBeUndefined();
};

/** The control: with no fault, an approved device's poll takes its approval once and gives a token. */
async function control(i: Instance) {
	const d = await approvedAt(i);
	expect(said(await pollAt(i, d))).toEqual([200, "Bearer"]);
	expect(successes(i, takeOf(d))).toHaveLength(1);
}

/** Healed: the topology has recovered and the instance is ready, and a newly approved device gives a token. */
async function healed(dep: Deployed, i: Instance) {
	await recovered(dep);
	await ready(i);
	expect(said(await pollAt(i, await approvedAt(i)))).toEqual([200, "Bearer"]);
}

/** The approval was never taken: once healed, the same device gives a token. */
async function stillApproved(dep: Deployed, i: Instance, d: Device) {
	await recovered(dep);
	await ready(i);
	expect(said(await pollAt(i, d))).toEqual([200, "Bearer"]);
}

describe("the token endpoint issuing no token for a device code while the store cannot answer", () => {
	it("gives no token while the network from the app to Redis is cut [guarantee-3-e] {fault:Pu}", async () => {
		await on({ name: "device-token-unavailable-pu" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await polledAt(i, d);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Nothing reached Redis while cut.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			expect(successes(i, takeOf(d))).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token while the network from Redis to the app is cut [guarantee-3-e] {fault:Pd}", async () => {
		await on({ name: "device-token-unavailable-pd" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await polledAt(i, d);
			i.relay.resume();
			noToken(answer);
			// The device's record was read on Redis, which answered before the endpoint gave up; the answer was held.
			expect(
				i.relay.executions(recordReadOf(d)).some((e) => e.at > stalled && e.at < answer.at),
			).toBe(true);
			expect(successes(i, takeOf(d))).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token while every connection to Redis is cut as it opens [guarantee-3-e] {fault:R}", async () => {
		await on({ name: "device-token-unavailable-r" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await polledAt(i, d).finally(() => clearInterval(cutting));
			noToken(answer);
			// The take, the write the guarantee rests on, did not succeed: cuts 20 ms apart cannot stop a
			// command getting through on a connection just opened, so only that write is checked.
			expect(successes(i, takeOf(d)).filter((e) => e.at > cut)).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token while Redis answers later than the command timeout [guarantee-3-e] {fault:L}", async () => {
		await on({ name: "device-token-unavailable-l" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await polledAt(i, d);
			i.relay.delay(0, "both");
			noToken(answer);
			// The device's record was read, and answered only after the endpoint had given up on it. (Not its
			// first call: the window it could not count lets the poll by, and the record's read is next.)
			await ready(i);
			expect(
				i.relay.executions(recordReadOf(d)).some((e) => e.at > delayed && e.at > answer.at),
			).toBe(true);
			expect(successes(i, takeOf(d))).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token while Redis is too slow to run commands [guarantee-3-e] {fault:S}", async () => {
		await on({ name: "device-token-unavailable-s" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const asking = performance.now();
			const { asleep, awake } = dep.topology.sleep(dep.topology.primary(), 5);
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await polledAt(i, d);
			noToken(answer);
			// The endpoint answered while Redis slept, before any of its calls was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				i.relay.executions(operations).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			expect(successes(i, takeOf(d))).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token while the primary holds its writes for a promotion [guarantee-3-e] {fault:F}", async () => {
		await on({ name: "device-token-unavailable-f" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const [next, ...others] = dep.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof polledAt>> | undefined;
			await dep.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					answer = await polledAt(i, d);
				},
			});
			repointed(dep);
			await replicasOnline(dep);
			if (!answer) throw new Error("the poll was not answered during the promotion");
			noToken(answer);
			expect(successes(i, takeOf(d))).toEqual([]);
			await stillApproved(dep, i, d);
			await healed(dep, i);
		});
	});

	it("gives no token for a poll whose approving session's entry is read on one server and confirmed on another [guarantee-3-e] {fault:Fs}", async () => {
		await on({ name: "device-token-unavailable-fs", replicas: 3 }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const old = dep.topology.primary();
			const [, moved, follower] = dep.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await dep.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			i.relay.switchUpstream(moved.upstream());
			i.relay.reset("operations");
			await reconnected(i, moved.upstream());
			const from = performance.now();
			const confirmed = i.relay.observe(confirmation({ replicas: 1 }));
			const answer = await polledAt(i, d);
			const wait = await confirmed;
			const upstreamOf = (id: number) => i.relay.connections().find((x) => x.id === id)?.upstream;
			// The poll read the device's record and then the approving session's entry on the new primary;
			// the entry's read is confirmed (the device's record is not), its round passing on the old one.
			const record = i.relay
				.executions(recordReadOf(d))
				.find((e) => e.at > from && runIdOf(e.reply) === newId);
			expect(record).toBeDefined();
			// The approving session's: the first entry read on the record's connection after it.
			const ran = i.relay
				.executions(sessionEntryRead)
				.find(
					(e) =>
						record !== undefined &&
						e.connection === record.connection &&
						e.at > record.at &&
						e.at < wait.at,
				);
			expect(ran && runIdOf(ran.reply)).toBe(newId);
			expect(ran && upstreamOf(ran.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			// The comparison refuses at the session entry's confirmation, before any take, so no take is
			// written. With the comparison taken out, the poll gives a token.
			expect(successes(i, takeOf(d)).filter((e) => e.at > from)).toEqual([]);
			noToken(answer);
			i.relay.reset("confirming");
			await healed(dep, i);
		});
	});

	it("gives a token from a poll made while Redis is killed at once and started again only where the server started again keeps its take [guarantee-3-e] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "device-token-unavailable-c" }, async (dep) => {
			const i = instanceOf(dep);
			await control(i);
			const d = await approvedAt(i);
			const from = performance.now();
			const holding = i.relay.hold(takeOf(d));
			const asked = polledAt(i, d);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it.
			i.relay.stall("up");
			const crashed = await dep.topology.crash(dep.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await dep.topology.primary().runId();
			repointed(dep);
			const restarted = performance.now();
			i.relay.resume();
			const answer = await asked;
			// Resent within its patience under its mark, the take may land on the server started again;
			// a token is given only so.
			const sent = i.relay.executions(takeOf(d)).filter((e) => e.at > from);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.status === 200) {
				const kept = sent.filter((e) => e.succeeded);
				expect(kept.length).toBeGreaterThan(0);
				expect(kept.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("given a token, its take kept on Redis started again");
			} else {
				noToken(answer);
				await annotate("answered temporarily_unavailable");
			}
			await replicasOnline(dep);
			await healed(dep, i);
		});
	});
});
