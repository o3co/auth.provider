import {
	confirmation,
	type Instance,
	instanceOf,
	keysOf,
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
	activeAt,
	issuedAt,
	on,
	revocationOf,
	revocationScene,
	revokedAt,
} from "../../faults/test/faults.ts";

// The area lets requests by uncounted where the store fails (rate-limit's fail-mode open), so each
// scene reaches the route's own calls: the store's clock, read for the write's deadline, then the
// token's revocation, answered only once confirmed.

const scene = revocationScene();
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
/** The store's clock read before a write, for its deadline: a script that names no key. */
const clockRead: Match = {
	request: (c) => c.name === "EVAL" && keysOf(c).length === 0,
	succeeded: () => true,
};

/** An answer at the moment it came. */
const revokedNow = async (i: Instance, token: string) => {
	const answer: Answer = await revokedAt(i, token);
	return { ...answer, at: performance.now() };
};
/** The answer under the fault: unavailable, never done. */
const unavailable = (answer: Answer) =>
	expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);

/** The control: with no fault, an active token's revocation is written once and answered done, and the token is inactive. */
async function control(i: Instance) {
	const token = await issuedAt(i);
	expect(await activeAt(i, token)).toBe(true);
	expect((await revokedAt(i, token)).status).toBe(200);
	expect(successes(i, revocationOf(token))).toHaveLength(1);
	expect(await activeAt(i, token)).toBe(false);
}

/** Healed: the instance is ready, the token revoked again is answered done and inactive, as is a new, active one. */
async function healed(i: Instance, token: string) {
	await ready(i);
	const fresh = await issuedAt(i);
	expect(await activeAt(i, fresh)).toBe(true);
	for (const t of [token, fresh]) {
		expect((await revokedAt(i, t)).status).toBe(200);
		expect(await activeAt(i, t)).toBe(false);
	}
}

describe("a revocation route answering done only once its revocation is kept", () => {
	it("answers unavailable while the network from the app to Redis is cut [guarantee-3-g] {fault:Pu}", async () => {
		await on({ name: "revocation-unavailable-pu", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const stalled = performance.now();
			i.relay.stall("up");
			const answer = await revokedNow(i, token);
			const resumed = performance.now();
			i.relay.resume();
			unavailable(answer);
			// Nothing reached Redis while cut.
			expect(i.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await healed(i, token);
		});
	});

	it("answers unavailable while the network from Redis to the app is cut, nothing revoked [guarantee-3-g] {fault:Pd}", async () => {
		await on({ name: "revocation-unavailable-pd", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const stalled = performance.now();
			i.relay.stall("down");
			const answer = await revokedNow(i, token);
			const resumed = performance.now();
			i.relay.resume();
			unavailable(answer);
			// Its clock read reached Redis, which answered it before the route gave up; the answer was held.
			expect(i.relay.executions(clockRead).some((e) => e.at > stalled && e.at < answer.at)).toBe(
				true,
			);
			expect(resumed).toBeGreaterThan(answer.at);
			// The route gave up before the revocation: the token is still active, and was not said revoked.
			await ready(i);
			expect(i.relay.executions(revocationOf(token))).toEqual([]);
			expect(await activeAt(i, token)).toBe(true);
			await healed(i, token);
		});
	});

	it("answers unavailable while every connection to Redis is cut as it opens [guarantee-3-g] {fault:R}", async () => {
		await on({ name: "revocation-unavailable-r", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const cut = performance.now();
			i.relay.reset("all");
			const cutting = setInterval(() => i.relay.reset("all"), 20);
			const answer = await revokedNow(i, token).finally(() => clearInterval(cutting));
			unavailable(answer);
			// Nothing reached Redis from the first cut to the answer.
			expect(i.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			await healed(i, token);
		});
	});

	it("answers unavailable while Redis answers later than the command timeout, nothing revoked [guarantee-3-g] {fault:L}", async () => {
		await on({ name: "revocation-unavailable-l", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			i.relay.delay(1_500, "both");
			const answer = await revokedNow(i, token);
			i.relay.delay(0, "both");
			unavailable(answer);
			// Its clock read was answered only after the route had given up on it, before the revocation.
			await ready(i);
			const read = i.relay.executions(clockRead).find((e) => e.at > delayed);
			expect(read?.at).toBeGreaterThan(answer.at);
			expect(i.relay.executions(revocationOf(token))).toEqual([]);
			expect(await activeAt(i, token)).toBe(true);
			await healed(i, token);
		});
	});

	it("answers unavailable while Redis is too slow to run commands [guarantee-3-g] {fault:S}", async () => {
		await on({ name: "revocation-unavailable-s", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const asking = performance.now();
			// Asleep past the write's patience (10 s): one shorter lets a resend after it wakes be confirmed, and the route answers done.
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 14);
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await revokedNow(i, token);
			unavailable(answer);
			// The route answered while Redis slept, before any revocation ran.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				i.relay.executions(revocationOf(token)).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			await healed(i, token);
		});
	});

	it("answers unavailable while the primary holds its writes for a promotion [guarantee-3-g] {fault:F}", async () => {
		await on({ name: "revocation-unavailable-f", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof revokedNow>> | undefined;
			let paused = 0;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					paused = performance.now();
					answer = await revokedNow(i, token);
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!answer) throw new Error("no answer while the writes were held");
			unavailable(answer);
			// Redis ran none of the route's calls while it held its writes: nothing was revoked.
			const held = answer.at;
			expect(
				i.relay
					.executions(anything)
					.filter((e) => e.command.name === "EVAL" && e.at > paused && e.at < held),
			).toEqual([]);
			expect(i.relay.executions(revocationOf(token))).toEqual([]);
			await healed(i, token);
		});
	});

	it("answers unavailable for a revocation written on a server other than the one that confirmed it [guarantee-3-g] {fault:Fs}", async () => {
		await on({ name: "revocation-unavailable-fs", scene, replicas: 3 }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
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
			const answer = await revokedNow(i, token);
			const wait = await confirmed;
			const upstreamOf = (id: number) => i.relay.connections().find((x) => x.id === id)?.upstream;
			// The revocation ran on the new primary, its confirmation passing on the old one.
			const written = i.relay
				.executions(revocationOf(token))
				.filter((e) => e.at > from && e.at < wait.at && runIdOf(e.reply) !== undefined)
				.at(-1);
			expect(written && runIdOf(written.reply)).toBe(newId);
			expect(written && upstreamOf(written.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			unavailable(answer);
			i.relay.reset("confirming");
			await healed(i, token);
		});
	});

	it("answers done for a revocation made while Redis is killed at once and started again only where the server started again keeps it [guarantee-3-g] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "revocation-unavailable-c", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await issuedAt(i);
			// The revocation held, then Redis killed under it: the write goes with its connection.
			const from = performance.now();
			const holding = i.relay.hold(revocationOf(token));
			const asked = revokedNow(i, token);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// writes the revocation comes after.
			i.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			i.relay.resume();
			const answer = await asked;
			// Resent within its patience, the revocation may land on the server started again, which
			// answers it; done is answered only so. A resend whose confirmation failed takes the answer
			// first written, so the answers are counted, each the held write under its mark.
			const sent = i.relay.executions(revocationOf(token)).filter((e) => e.at > from);
			const given = sent.filter((e) => e.succeeded);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.status === 200) {
				expect(given.length).toBeGreaterThan(0);
				expect(given.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("answered done for a revocation kept on Redis started again");
			} else {
				unavailable(answer);
				await annotate("answered temporarily_unavailable");
			}
			await replicasOnline(d);
			await healed(i, token);
		});
	});
});
