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
	familyAt,
	faultScene,
	on,
	refreshAt,
	said,
} from "../../faults/test/faults.ts";
import { familyRead, isStoreOperation, rotationFrom, sessionRead } from "../../faults/test/wire.ts";

// The area lets requests go uncounted where the store fails (rate-limit's fail-mode open), so each
// scene reaches the refresh's own decision: the read of the family's record, then its rotation.

const scene = faultScene({ refresh: {} });

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/** The answer under the fault: unavailable, with no token. */
const unavailable = [503, "temporarily_unavailable"];
/** A refresh's answer at the moment it came. */
const refreshedAt = async (i: Instance, token: string) => {
	const answer: Answer = await refreshAt(i, token);
	return { ...answer, at: performance.now() };
};
const noToken = (answer: Answer) => {
	expect(said(answer)).toEqual(unavailable);
	expect(answer.body.access_token).toBeUndefined();
};

/** The control: with no fault, a family is rotated by one write and a token is issued from it. */
async function control(i: Instance) {
	const token = await familyAt(i);
	expect(said(await refreshAt(i, token))).toEqual([200, "Bearer"]);
	expect(successes(i, rotationFrom(token))).toHaveLength(1);
}

/** Healed: the topology has recovered and the instance is ready, and a new family is rotated. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	expect(said(await refreshAt(i, await familyAt(i)))).toEqual([200, "Bearer"]);
}

describe("the token endpoint issuing no token for a refresh token while the store cannot answer", () => {
	it("gives no token while the network from the app to Redis is cut [guarantee-3-c] {fault:Pu}", async () => {
		await on({ name: "refresh-token-unavailable-pu", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await refreshedAt(i, token);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Nothing reached Redis while cut: what it sent then is answered only once resumed.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(i);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the network from Redis to the app is cut [guarantee-3-c] {fault:Pd}", async () => {
		await on({ name: "refresh-token-unavailable-pd", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await refreshedAt(i, token);
			const resumed = performance.now();
			i.relay.resume();
			noToken(answer);
			// Its read of the family reached Redis, which answered it before the endpoint gave up; the answer was held.
			expect(i.relay.executions(familyRead).some((e) => e.at > stalled && e.at < answer.at)).toBe(
				true,
			);
			expect(resumed).toBeGreaterThan(answer.at);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while every connection to Redis is cut as it opens [guarantee-3-c] {fault:R}", async () => {
		await on({ name: "refresh-token-unavailable-r", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await refreshedAt(i, token).finally(() => clearInterval(cutting));
			noToken(answer);
			// Nothing reached Redis from the first cut to the answer.
			expect(i.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis answers later than the command timeout [guarantee-3-c] {fault:L}", async () => {
		await on({ name: "refresh-token-unavailable-l", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await refreshedAt(i, token);
			i.relay.delay(0, "both");
			noToken(answer);
			// Its read of the family was answered only after the endpoint had given up on it.
			await ready(i);
			const read = i.relay.executions(familyRead).find((e) => e.at > delayed);
			expect(read?.at).toBeGreaterThan(answer.at);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while Redis is too slow to run commands [guarantee-3-c] {fault:S}", async () => {
		await on({ name: "refresh-token-unavailable-s", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the endpoint's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await refreshedAt(i, token);
			noToken(answer);
			// The endpoint answered while Redis slept, before any read of the family was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				i.relay.executions(familyRead).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token while the primary holds its writes for a promotion [guarantee-3-c] {fault:F}", async () => {
		await on({ name: "refresh-token-unavailable-f", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof refreshedAt>> | undefined;
			let paused = 0;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					paused = performance.now();
					answer = await refreshedAt(i, token);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("no answer while the writes were held");
			noToken(answer);
			// Redis ran none of the refresh's calls while it held its writes: the family was not rotated.
			const held = answer.at;
			expect(
				i.relay
					.executions(anything)
					.filter((e) => isStoreOperation(e.command) && e.at > paused && e.at < held),
			).toEqual([]);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			await healed(d, i);
		});
	});

	it("gives no token for a read of the session confirmed on a server other than the one that answered it [guarantee-3-c] {fault:Fs}", async () => {
		await on({ name: "refresh-token-unavailable-fs", scene, replicas: 3 }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			i.relay.switchUpstream(moved.upstream());
			i.relay.reset("operations");
			await reconnected(i, moved.upstream());
			const from = performance.now();
			const confirmed = i.relay.observe(confirmation({ replicas: 1 }));
			const answer = await refreshedAt(i, token);
			const wait = await confirmed;
			const upstreamOf = (id: number) => i.relay.connections().find((x) => x.id === id)?.upstream;
			// The family's record was read on the new primary, then its session's entry on the same
			// connection, whose read is confirmed: it ran there, its confirmation passing on the old one;
			// so the decision stopped there, before the rotation.
			const family = i.relay
				.executions(familyRead)
				.find((e) => e.at > from && runIdOf(e.reply) === newId);
			expect(family).toBeDefined();
			const read = i.relay
				.executions(sessionRead)
				.find(
					(e) =>
						family !== undefined &&
						e.connection === family.connection &&
						e.at > family.at &&
						e.at < wait.at,
				);
			expect(read && runIdOf(read.reply)).toBe(newId);
			expect(read && upstreamOf(read.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			noToken(answer);
			expect(successes(i, rotationFrom(token))).toEqual([]);
			i.relay.reset("confirming");
			await healed(d, i);
		});
	});

	it("gives no token from a decision made while Redis is killed at once and started again [guarantee-3-c] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "refresh-token-unavailable-c", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await familyAt(i);
			// The family's rotation held, then Redis killed under it: the write goes with its connection.
			const from = performance.now();
			const holding = i.relay.hold(rotationFrom(token));
			const asked = refreshedAt(i, token);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// rotates the family comes after.
			i.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			i.relay.resume();
			const answer = await asked;
			// Resent within its patience, the rotation may land on the server started again, which answers
			// it; a token is given only so. A resend whose confirmation failed takes the answer first
			// written, so the answers are counted, each the held write under its mark.
			const sent = i.relay.executions(rotationFrom(token)).filter((e) => e.at > from);
			const given = sent.filter((e) => e.succeeded);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.status === 200) {
				expect(given.length).toBeGreaterThan(0);
				expect(given.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("given a token for a rotation kept on Redis started again");
			} else {
				noToken(answer);
				await annotate("answered temporarily_unavailable");
			}
			await healed(d, i);
		});
	});
});
