import { auditStandIn } from "@mod/audit/testing";
import { type Eraser, erasers } from "@mod/erasure-extensions";
import {
	type Assembly,
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Key, type Store, store } from "@mod/store";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { type LockoutPolicy, type Lockouts, lockouts, subjectLockouts } from "../src/contract.ts";
import { lockoutEraser } from "../src/drop/drop.ts";
import { lockoutSpace, storedStates } from "../src/lockout/lockout.ts";
import rateLimitModule from "../src/module.ts";
import { partitionOf } from "../src/partition.ts";
import { rateLimitStandIn } from "../src/testing.ts";

const start = 1_800_000_000_000;
let now = start;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

const policy: LockoutPolicy = {
	threshold: 2,
	backoffMs: 1000,
	maxBackoffMs: 4000,
	budget: 5,
	budgetWindowMs: 60_000,
	hardLimit: 6,
	memoryMs: 60_000,
};

const seen = contract<readonly Eraser[]>("drop-test.erasers");
/** Names its lockouts by subject, and hands the erasers composed to the test. */
const names = (...lockoutNames: readonly string[]) =>
	defineModule({ name: "names", replicaSafe: true, takes: [erasers] }, (m) => [
		...lockoutNames.map((name) => m.contribute(subjectLockouts).by(() => ({ name }))),
		m.provide(seen).by((c) => c.collect(erasers)),
	]);

const eraserIn = (app: Assembly) => {
	const [eraser] = app.get(seen);
	if (eraser === undefined) throw new Error("no eraser composed");
	return eraser;
};
const signal = () => new AbortController().signal;
const outcome = (run: Promise<unknown>) =>
	run.then(
		(value) => ({ value }),
		(error: unknown) => (isUnavailable(error) ? "unavailable" : { error: String(error) }),
	);

/** Every entry point on one key, each answering or failing as it does. */
async function everyEntry(l: Lockouts, name: string, key: string) {
	return {
		check: await outcome(l.check(name, key, policy)),
		standing: await outcome(l.standing(name, key, policy)),
		failed: await outcome(l.failed(name, key, policy)),
		reserve: await outcome(l.reserve(name, key, policy)),
		succeeded: await outcome(l.succeeded(name, key, policy, start)),
		succeededBare: await outcome(l.succeeded(name, key, policy)),
		abandoned: await outcome(l.abandoned(name, key, policy, start)),
		checked: await outcome(
			l.releaseUnder(name, key, policy, {
				kind: "checked",
				once: { id: "r1", keepMs: 60_000 },
				forgive: {},
			}),
		),
		whole: await outcome(l.releaseUnder(name, key, policy, { kind: "whole" })),
	};
}
const unavailableEverywhere = {
	check: "unavailable",
	standing: "unavailable",
	failed: "unavailable",
	reserve: "unavailable",
	succeeded: "unavailable",
	succeededBare: "unavailable",
	abandoned: "unavailable",
	checked: "unavailable",
	whole: "unavailable",
};

/** Runs the same calls on the real module over a store and on the stand-in, from the same instant. */
async function both<T>(lockoutNames: readonly string[], run: (app: Assembly) => Promise<T>) {
	const compositions: Module[][] = [
		[rateLimitModule, simulatedStore().module, auditStandIn().module, names(...lockoutNames)],
		[rateLimitStandIn, names(...lockoutNames)],
	];
	const answers: T[] = [];
	for (const modules of compositions) {
		now = start;
		answers.push(await run(await assemble({ modules, config: kernelConfig(), runtime })));
	}
	return answers;
}

async function stored(...lockoutNames: readonly string[]) {
	now = start;
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [rateLimitModule, simulated.module, auditStandIn().module, names(...lockoutNames)],
		config: kernelConfig(),
		runtime,
	});
	return { simulated, app, store: app.get(store), lockouts: app.get(lockouts) };
}
const keyOf = (name: string, key: string): Key => ({
	space: lockoutSpace,
	partition: partitionOf(name, key),
	name: "lockout",
});

it("drops a subject's key under each name composed, after which every entry point is unavailable, on the real module and the stand-in alike", async () => {
	const [real, standIn] = await both(["mfa", "other"], async (app) => {
		const l = app.get(lockouts);
		await l.failed("mfa", "alice", policy);
		await l.failed("mfa", "bob", policy);
		await l.failed("free", "alice", policy);
		const eraser = eraserIn(app);
		const first = await eraser.online("alice", signal());
		const again = await eraser.online("alice", signal());
		return {
			eraser: { name: eraser.name, erasable: eraser.erasable, after: eraser.after },
			first,
			again,
			mfa: await everyEntry(l, "mfa", "alice"),
			// An absent key is dropped too, so a write landing later meets it.
			other: await everyEntry(l, "other", "alice"),
			// Another subject, and a name not composed, are left as they were.
			bob: await l.check("mfa", "bob", policy),
			free: await l.standing("free", "alice", policy),
			migrated: await eraser.migrate({ sweep: async () => ({ keys: [], server: "s" }) }, signal()),
		};
	});
	expect(standIn).toEqual(real);
	expect(real).toEqual({
		eraser: { name: "rate-limit", erasable: true, after: undefined },
		first: {
			reports: [{ kind: "forgotten", space: "rate-limit.lockouts", removed: 1 }],
			logoutGaps: 0,
		},
		again: {
			reports: [{ kind: "forgotten", space: "rate-limit.lockouts", removed: 0 }],
			logoutGaps: 0,
		},
		mfa: unavailableEverywhere,
		other: unavailableEverywhere,
		bob: { kind: "open" },
		free: { firstFailureAt: start },
		migrated: [],
	});
});

it("drops each subject of a window, in one report counting the states it dropped", async () => {
	const [real, standIn] = await both(["mfa"], async (app) => {
		const l = app.get(lockouts);
		await l.failed("mfa", "alice", policy);
		await l.failed("mfa", "bob", policy);
		const walk = { sweep: async () => ({ keys: [], server: "s" }) };
		const erased = await eraserIn(app).window(["alice", "bob", "carol"], walk, signal());
		return { erased, carol: await outcome(l.check("mfa", "carol", policy)) };
	});
	expect(standIn).toEqual(real);
	expect(real).toEqual({
		erased: {
			reports: [{ kind: "forgotten", space: "rate-limit.lockouts", removed: 2 }],
			logoutGaps: 0,
		},
		carol: "unavailable",
	});
});

it("writes the dropped value at the very key a failure wrote, never expiring, and leaves it as it is through every entry point", async () => {
	const { store: s, lockouts: l, app } = await stored("mfa");
	await l.failed("mfa", "alice", policy);
	const key = keyOf("mfa", "alice");
	expect((await s.get(key)).entry?.value).toMatchObject({ run: 1 });
	await eraserIn(app).online("alice", signal());
	const { entry } = await s.get(key);
	expect(entry?.value).toEqual({ dropped: 1 });
	expect(entry?.expiresAt).toBeNull();
	expect(await everyEntry(l, "mfa", "alice")).toEqual(unavailableEverywhere);
	expect((await s.get(key)).entry?.version).toBe(entry?.version);
	// A release's terms refused before the read write nothing either, its own error thrown.
	const refused = l.releaseUnder("mfa", "alice", policy, {
		kind: "checked",
		once: { id: "r2", keepMs: 0 },
	});
	await expect(refused).rejects.toThrow(/keepMs/);
	expect((await s.get(key)).entry?.version).toBe(entry?.version);
});

it("drops an expired key and one of another shape, counting neither, and reads the pinned value as dropped", async () => {
	const { store: s, lockouts: l, app } = await stored("mfa", "odd", "pinned");
	const state = { run: 1, lastAt: start, spent: [start], holdUntil: 0, fixed: false };
	await s.putIfAbsent(keyOf("mfa", "alice"), state, { expiry: { kind: "after", ms: 1000 } });
	await s.putIfAbsent(keyOf("odd", "alice"), { dropped: 1, run: 1 }, { expiry: { kind: "never" } });
	await s.putIfAbsent(keyOf("pinned", "bob"), { dropped: 1 }, { expiry: { kind: "never" } });
	now += 1000;
	expect(await l.check("mfa", "alice", policy)).toEqual({ kind: "open" });
	await expect(l.check("odd", "alice", policy)).rejects.toSatisfy(isUnavailable);
	await expect(l.check("pinned", "bob", policy)).rejects.toSatisfy(isUnavailable);
	const erased = await eraserIn(app).window(
		["alice", "bob"],
		{ sweep: async () => ({ keys: [], server: "s" }) },
		signal(),
	);
	expect(erased.reports).toEqual([{ kind: "forgotten", space: "rate-limit.lockouts", removed: 0 }]);
	for (const [name, key] of [
		["mfa", "alice"],
		["odd", "alice"],
		["pinned", "bob"],
	] as const) {
		expect((await s.get(keyOf(name, key))).entry?.value).toEqual({ dropped: 1 });
	}
});

it("throws the signal's reason when cut short between names, keeping the keys it dropped, and a next run finishes", async () => {
	const { store: s, lockouts: l } = await stored();
	await l.failed("a", "alice", policy);
	await l.failed("b", "alice", policy);
	const controller = new AbortController();
	const reason = new Error("stopped by the operator");
	const states = storedStates(s);
	const cutting = {
		...states,
		change: async (...args: Parameters<typeof states.change>) => {
			await states.change(...args);
			controller.abort(reason);
		},
	};
	const eraser = lockoutEraser(cutting, [{ name: "b" }, { name: "a" }]);
	await expect(eraser.online("alice", controller.signal)).rejects.toBe(reason);
	await expect(l.check("a", "alice", policy)).rejects.toSatisfy(isUnavailable);
	expect((await l.check("b", "alice", policy)).kind).toBe("open");
	const finished = await lockoutEraser(states, [{ name: "a" }, { name: "b" }]).online(
		"alice",
		signal(),
	);
	expect(finished.reports).toEqual([
		{ kind: "forgotten", space: "rate-limit.lockouts", removed: 1 },
	]);
	await expect(l.check("b", "alice", policy)).rejects.toSatisfy(isUnavailable);
});

/** Runs the eraser just before the next write of a lockout lands, as an erasure racing it would. */
const dropBefore = (simulated: SimulatedStore, app: Assembly, operation: keyof Store) =>
	simulated.beforeNext(operation, lockoutSpace.name, async () => {
		await eraserIn(app).online("alice", signal());
	});

it("leaves nothing a late write could make: a failure landing after the drop, a reservation crossing it, a whole release after it", async () => {
	const { simulated, store: s, lockouts: l, app } = await stored("mfa");
	const key = keyOf("mfa", "alice");
	// A failure decided on an absent key, the drop landing before its write: it meets the drop.
	dropBefore(simulated, app, "putIfAbsent");
	await expect(l.failed("mfa", "alice", policy)).rejects.toSatisfy(isUnavailable);
	expect((await s.get(key)).entry?.value).toEqual({ dropped: 1 });

	// A reservation taken before the drop: the guess judged after it hands nothing back, either way.
	const { store: s2, lockouts: l2, app: app2 } = await stored("mfa");
	const reserved = await l2.reserve("mfa", "alice", policy);
	expect(reserved.kind).toBe("open");
	const reservation = reserved.kind === "open" ? reserved.reservation : 0;
	await eraserIn(app2).online("alice", signal());
	await expect(l2.succeeded("mfa", "alice", policy, reservation)).rejects.toSatisfy(isUnavailable);
	await expect(l2.abandoned("mfa", "alice", policy, reservation)).rejects.toSatisfy(isUnavailable);
	expect((await s2.get(key)).entry?.value).toEqual({ dropped: 1 });

	// A reset's whole release decided on a held key, the drop landing before its write: it meets the drop.
	const { simulated: s3, store: st3, lockouts: l3, app: app3 } = await stored("mfa");
	await l3.failed("mfa", "alice", policy);
	dropBefore(s3, app3, "replaceIf");
	await expect(l3.releaseUnder("mfa", "alice", policy, { kind: "whole" })).rejects.toSatisfy(
		isUnavailable,
	);
	expect((await st3.get(key)).entry?.value).toEqual({ dropped: 1 });
});

it("refuses the boot where a lockout name is contributed twice", async () => {
	const twice = defineModule({ name: "twice", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(subjectLockouts).by(() => ({ name: "mfa" })),
	]);
	const booted = assemble({
		modules: [rateLimitStandIn, names("mfa"), twice],
		config: kernelConfig(),
		runtime,
	});
	await expect(booted).rejects.toBeInstanceOf(BootRefused);
});

it("throws the signal's reason for a run cut short before it starts, with no names, no subjects, or a migration", async () => {
	const { store: s } = await stored();
	const controller = new AbortController();
	const reason = new Error("stopped before it began");
	controller.abort(reason);
	const walk = { sweep: async () => ({ keys: [], server: "s" }) };
	const none = lockoutEraser(storedStates(s), []);
	await expect(none.online("alice", controller.signal)).rejects.toBe(reason);
	await expect(none.window([], walk, controller.signal)).rejects.toBe(reason);
	await expect(none.migrate(walk, controller.signal)).rejects.toBe(reason);
});

it("counts a state past its expiry as gone, on the real module and the stand-in alike", async () => {
	const [real, standIn] = await both(["mfa"], async (app) => {
		const l = app.get(lockouts);
		await l.failed("mfa", "alice", policy);
		// Past the longer of the budget window and the memory, a state no hold fixed has expired.
		now += policy.budgetWindowMs + policy.memoryMs;
		return eraserIn(app).online("alice", signal());
	});
	expect(standIn).toEqual(real);
	expect(real?.reports).toEqual([{ kind: "forgotten", space: "rate-limit.lockouts", removed: 0 }]);
});
