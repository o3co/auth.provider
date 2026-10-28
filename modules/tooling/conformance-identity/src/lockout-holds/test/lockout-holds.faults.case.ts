import { randomUUID } from "node:crypto";
import {
	confirmation,
	failover,
	type Instance,
	instanceOf,
	ready,
	replicasOnline,
	repointed,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	type Answer,
	faultScene,
	loginAt,
	nextSource,
	on,
	said,
} from "../../faults/test/faults.ts";
import { isStoreOperation, lockoutOf, lockoutRun } from "../../faults/test/wire.ts";

// How many failures an identifier's run holds is read from the state each counted attempt writes, its
// run; a wait is read from an answer only where it is long enough (4 s and more) that no slow host
// lets it lapse before the next attempt comes.

// The scene's value, not the default (10): the first failure at an identifier starts its wait, which
// doubles with each failure after it (1 s, 2 s, 4 s, …), so a run of three asks a wait of 4 s.
const counting = faultScene({ login: { accountAttempts: 1 } });
// The scene's value, not the default (10): two attempts at once start no wait between them, so both are
// judged as attempts and counted.
const twoAtOnce = faultScene({ login: { accountAttempts: 3 } });

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** An identifier of its own, held by no account: attempts at it are counted alike. */
const nextIdentifier = () => `guess-${randomUUID()}`;
/** A wrong password for the identifier, from a source of its own, so only the identifier's count holds it back. */
const failAt = (i: Instance, identifier: string) =>
	loginAt(i, nextSource(), { username: identifier, password: "not-the-password" });

const failed = [401, "invalid_credentials", false];
/** Held back as the identifier waits, its password not checked. */
const waiting = (a: Answer) => {
	expect(said(a)).toEqual([429, "too_many_attempts", false]);
	return a.retryAfter ?? 0;
};
/** Refused as the count could not be made or confirmed. */
const uncounted = [503, "service_unavailable", false];

/** The runs the identifier's counted attempts wrote, at each of the instances, in no order across them. */
const runsAt = (identifier: string, ...instances: Instance[]) =>
	instances.flatMap((i) => successes(i, lockoutOf(identifier)).map((e) => lockoutRun(e.command)));

/** The control: with no fault, each failure is counted by one write, its run one longer than the last. */
async function control(i: Instance) {
	const identifier = nextIdentifier();
	for (let n = 1; n <= 2; n++) {
		expect(said(await failAt(i, identifier))).toEqual(failed);
		await pause(1_000 * 2 ** (n - 1) + 200);
	}
	expect(runsAt(identifier, i)).toEqual([1, 2]);
}

/** `run` failures at the identifier, each after the wait the one before started, so each is counted. */
async function failuresAt(i: Instance, identifier: string, run: number) {
	for (let n = 1; n <= run; n++) {
		expect(said(await failAt(i, identifier))).toEqual(failed);
		await pause(1_000 * 2 ** (n - 1) + 200);
	}
	expect(runsAt(identifier, i).at(-1)).toBe(run);
}

/**
 * The run of `run` failures held: the next failure writes run + 1, never 1 as a run forgotten would, and
 * starts a wait of 2^run s, long enough that the attempt right after it is held back.
 */
async function heldAt(i: Instance, identifier: string, run: number) {
	expect(said(await failAt(i, identifier))).toEqual(failed);
	expect(runsAt(identifier, i).at(-1)).toBe(run + 1);
	expect(waiting(await failAt(i, identifier))).toBeGreaterThan(2 ** (run - 1));
}

/** Healed: the instance is ready, and a new identifier's failure is counted as the first of its run. */
async function healed(i: Instance) {
	await ready(i);
	const identifier = nextIdentifier();
	expect(said(await failAt(i, identifier))).toEqual(failed);
	expect(runsAt(identifier, i)).toEqual([1]);
}

describe("password login's per-identifier count holding under faults", () => {
	it("counts an attempt once whose reservation's answer is lost, refusing it, never twice [guarantee-5-i] {fault:Lr}", async () => {
		await on({ name: "lockout-holds-lr", scene: counting }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const identifier = nextIdentifier();
			await failuresAt(a, identifier, 2);
			const drop = a.relay.dropReplyTo(lockoutOf(identifier));
			const answer = await failAt(a, identifier);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => isStoreOperation(x.command))).toEqual([]);
			// The reservation took effect, unheard: the attempt is refused, and stays a failure.
			expect(said(answer)).toEqual(uncounted);
			await ready(a);
			// A lockout's write carries no mark to resend under, and none was sent again: counted once.
			expect(runsAt(identifier, a)).toEqual([1, 2, 3]);
			// The run of three waits 4 s: the attempt right after is held back, writing nothing.
			const wait = waiting(await failAt(a, identifier));
			expect(wait).toBeGreaterThan(2);
			expect(wait).toBeLessThanOrEqual(4);
			expect(runsAt(identifier, a)).toEqual([1, 2, 3]);
			await healed(a);
		});
	});

	it("holds an identifier's count across a caught-up replica's promotion [guarantee-5-i] {fault:F}", async () => {
		await on({ name: "lockout-holds-f", scene: counting }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const identifier = nextIdentifier();
			await failuresAt(a, identifier, 2);
			await failover(d);
			await ready(a);
			await heldAt(a, identifier, 2);
			await healed(a);
		});
	});

	it("holds an identifier's count across Redis killed at once and started again [guarantee-5-i] {fault:C}", async () => {
		await on({ name: "lockout-holds-c", scene: counting }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const identifier = nextIdentifier();
			await failuresAt(a, identifier, 2);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(a);
			await heldAt(a, identifier, 2);
			await healed(a);
		});
	});

	it("holds, at another instance, an attempt whose instance was killed after counting it and before answering [guarantee-5-i] {fault:K}", async () => {
		await on({ name: "lockout-holds-k", scene: counting, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const identifier = nextIdentifier();
			await failuresAt(a, identifier, 3);
			// The reservation's confirmation held once it has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const counted = a.relay.observe(lockoutOf(identifier)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = failAt(a, identifier).catch(() => undefined);
			await counted;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			// No answer from the instance: the trace in front of it answers 502 for one gone.
			expect([undefined, 502]).toContain((await answer)?.status);
			expect(runsAt(identifier, a)).toEqual([1, 2, 3, 4]);
			// The fourth failure started a wait of 8 s: B's attempt is held back; unheld, it would be the fourth.
			await ready(b);
			expect(waiting(await failAt(b, identifier))).toBeGreaterThan(0);
			expect(runsAt(identifier, b)).toEqual([]);
			await healed(b);
		});
	});

	// A lockout counts; it is not used once. Let go one after the other, both attempts are counted, one
	// each; let go together, each is counted at most once, one that keeps losing the race is refused as
	// unavailable, and no attempt goes on uncounted.

	it("counts both of two attempts at an identifier at two instances, let go one after the other [guarantee-5-i] {fault:H2}", async () => {
		await on({ name: "lockout-holds-h2", scene: twoAtOnce, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const identifier = nextIdentifier();
			// Both have read the identifier's state and are about to count on it.
			const [heldA, heldB] = [
				a.relay.hold(lockoutOf(identifier)),
				b.relay.hold(lockoutOf(identifier)),
			];
			const [atA, atB] = [failAt(a, identifier), failAt(b, identifier)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect(said(await atA)).toEqual(failed);
			second.release();
			expect(said(await atB)).toEqual(failed);
			// The later one lost its race, read the run again and counted on it: 1, then 2.
			expect(runsAt(identifier, a, b).sort()).toEqual([1, 2]);
			// The next attempt at either counts on both: a third.
			expect(said(await failAt(a, identifier))).toEqual(failed);
			expect(runsAt(identifier, a, b).sort()).toEqual([1, 2, 3]);
			await healed(a);
		});
	});

	it("counts each of two attempts at an identifier at two instances, let go together, at most once and none uncounted [guarantee-5-i] {fault:H2}", async () => {
		await on({ name: "lockout-holds-h2-together", scene: twoAtOnce, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const identifier = nextIdentifier();
			const holds = [a.relay.hold(lockoutOf(identifier)), b.relay.hold(lockoutOf(identifier))];
			const answers = Promise.all([failAt(a, identifier), failAt(b, identifier)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = await answers;
			// Each answered as counted (a failure) or refused unavailable; each failure counted once.
			for (const x of both) expect([failed, uncounted]).toContainEqual(said(x));
			const judged = both.filter((x) => x.status === 401).length;
			expect(judged).toBeGreaterThan(0);
			const runs = runsAt(identifier, a, b).sort();
			expect(runs).toEqual(Array.from({ length: judged }, (_, n) => n + 1));
			// The next attempt counts on all of them.
			expect(said(await failAt(b, identifier))).toEqual(failed);
			expect(runsAt(identifier, a, b).sort()).toEqual([...runs, judged + 1]);
			await healed(a);
		});
	});
});
