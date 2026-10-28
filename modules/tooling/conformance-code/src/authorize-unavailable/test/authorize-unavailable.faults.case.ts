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
import { app, browserOn, callback, on, pkce } from "../../faults/test/faults.ts";
import { codeKept, cookieRead } from "../../faults/test/wire.ts";

/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/** A browser logged in at the instance, before any fault. */
async function loggedInAt(i: Instance) {
	const browser = browserOn(i);
	await browser.login();
	return browser;
}

/** The authorization endpoint's answer to `app`'s request: where it sends the browser, read. */
async function authorize(browser: ReturnType<typeof browserOn>) {
	const { challenge } = pkce();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const back = res.at && `${res.at.origin}${res.at.pathname}` === callback ? res.at : undefined;
	return {
		status: res.status,
		code: back?.searchParams.get("code") ?? undefined,
		error: back?.searchParams.get("error") ?? undefined,
		at: performance.now(),
	};
}

/** The client's answer under the fault: a redirect to it with temporarily_unavailable, and no code. */
const unavailable = { status: 302, code: undefined, error: "temporarily_unavailable" };
const shape = (a: Awaited<ReturnType<typeof authorize>>) => ({
	status: a.status,
	code: a.code,
	error: a.error,
});

/** The control: with no fault, the endpoint keeps one new code and gives it. */
async function control(i: Instance) {
	const browser = await loggedInAt(i);
	const before = successes(i, codeKept).length;
	const answer = await authorize(browser);
	expect(answer.code).toBeTruthy();
	expect(successes(i, codeKept).length).toBe(before + 1);
}

/** Healed: the topology has recovered and the instance is ready, and a new request is given a code. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	expect((await authorize(await loggedInAt(i))).code).toBeTruthy();
}

describe("the authorization endpoint issuing no code while the store cannot answer", () => {
	it("gives no code while the network from the app to Redis is cut [guarantee-3-a] {fault:Pu}", async () => {
		await on({ name: "authorize-unavailable-pu" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const stalled = performance.now();
			a.relay.stall("up");
			const answer = await authorize(browser);
			const resumed = performance.now();
			a.relay.resume();
			expect(shape(answer)).toEqual(unavailable);
			// Nothing reached Redis while cut: the read it sent then is answered only once resumed.
			expect(a.relay.executions(anything).filter((e) => e.at > stalled && e.at < resumed)).toEqual(
				[],
			);
			await ready(a);
			expect(a.relay.executions(cookieRead).some((e) => e.at > resumed)).toBe(true);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code while the network from Redis to the app is cut [guarantee-3-a] {fault:Pd}", async () => {
		await on({ name: "authorize-unavailable-pd" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const stalled = performance.now();
			a.relay.stall("down");
			const answer = await authorize(browser);
			const resumed = performance.now();
			a.relay.resume();
			expect(shape(answer)).toEqual(unavailable);
			// Its read reached Redis, which answered it before the endpoint gave up; the answer was held.
			expect(a.relay.executions(cookieRead).some((e) => e.at > stalled && e.at < answer.at)).toBe(
				true,
			);
			expect(resumed).toBeGreaterThan(answer.at);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code while every connection to Redis is cut as it opens [guarantee-3-a] {fault:R}", async () => {
		await on({ name: "authorize-unavailable-r" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const cut = performance.now();
			a.relay.reset("all");
			const cutting = setInterval(() => a.relay.reset("all"), 20);
			const answer = await authorize(browser).finally(() => clearInterval(cutting));
			expect(shape(answer)).toEqual(unavailable);
			// Nothing reached Redis from the first cut to the answer.
			expect(a.relay.executions(anything).filter((e) => e.at > cut && e.at < answer.at)).toEqual(
				[],
			);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code while Redis answers later than the command timeout [guarantee-3-a] {fault:L}", async () => {
		await on({ name: "authorize-unavailable-l" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const delayed = performance.now();
			// Past the command timeout (1 s by default) each way.
			a.relay.delay(1_500, "both");
			const answer = await authorize(browser);
			a.relay.delay(0, "both");
			expect(shape(answer)).toEqual(unavailable);
			// Its read was answered only after the endpoint had given up on it.
			await ready(a);
			const read = a.relay.executions(cookieRead).find((e) => e.at > delayed);
			expect(read && read.at).toBeGreaterThan(answer.at);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code while Redis is too slow to run commands [guarantee-3-a] {fault:S}", async () => {
		await on({ name: "authorize-unavailable-s" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const asking = performance.now();
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 5);
			// When Redis woke, taken as it wakes, apart from the endpoint's answer.
			const woke = awake.then(() => performance.now());
			await asleep;
			const answer = await authorize(browser);
			expect(shape(answer)).toEqual(unavailable);
			// The endpoint answered while Redis slept, before any read of it was answered.
			expect(answer.at).toBeLessThan(await woke);
			expect(
				a.relay.executions(cookieRead).filter((e) => e.at > asking && e.at < answer.at),
			).toEqual([]);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code while the primary holds its writes for a promotion [guarantee-3-a] {fault:F}", async () => {
		await on({ name: "authorize-unavailable-f" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			const kept = successes(a, codeKept).length;
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			let answer: Awaited<ReturnType<typeof authorize>> | undefined;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					answer = await authorize(browser);
				},
			});
			repointed(d);
			await replicasOnline(d);
			expect(answer && shape(answer)).toEqual(unavailable);
			expect(successes(a, codeKept).length).toBe(kept);
			await healed(d, a);
		});
	});

	it("gives no code kept on a server other than the one that confirmed it [guarantee-3-a] {fault:Fs}", async () => {
		await on({ name: "authorize-unavailable-fs", replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
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
			const answer = await authorize(browser);
			const wait = await confirmed;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			// A write the decision made ran on the new primary, its confirmation passing on the old one.
			const first = a.relay
				.executions(anything)
				.filter(
					(e) =>
						e.at > from &&
						e.at < wait.at &&
						e.command.name === "EVAL" &&
						runIdOf(e.reply) !== undefined,
				)
				.at(-1);
			expect(first && runIdOf(first.reply)).toBe(newId);
			expect(first && upstreamOf(first.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			expect(shape(answer)).toEqual(unavailable);
			a.relay.reset("confirming");
			await healed(d, a);
		});
	});

	it("gives no code from a decision made while Redis is killed at once and started again [guarantee-3-a] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "authorize-unavailable-c" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const browser = await loggedInAt(a);
			// The code's write held, then Redis killed under it: the write goes with its connection.
			const from = performance.now();
			const holding = a.relay.hold(codeKept);
			const asked = authorize(browser);
			const held = await holding;
			// Nothing reaches Redis until it is started again and the relay points at it, so all that
			// keeps the code comes after.
			a.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			a.relay.resume();
			const answer = await asked;
			// Resent within its patience, the write may land on the server started again, which
			// answers it; a code is given only so. A resend whose confirmation failed takes the answer
			// first written, so the answers are counted, each the held write under its mark.
			const sent = a.relay.executions(codeKept).filter((e) => e.at > from);
			const given = sent.filter((e) => e.succeeded);
			expect(sent.every((e) => sameMark(held.command, e.command))).toBe(true);
			if (answer.code) {
				expect(given.length).toBeGreaterThan(0);
				expect(given.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				await annotate("given a code kept on Redis started again");
			} else {
				expect(shape(answer)).toEqual(unavailable);
				await annotate("answered temporarily_unavailable");
			}
			await replicasOnline(d);
			await healed(d, a);
		});
	});
});
