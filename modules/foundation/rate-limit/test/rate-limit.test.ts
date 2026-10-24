import { auditStandIn } from "@mod/audit/testing";
import { listening, routes, use } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { metrics } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
	attemptLimit,
	attemptsPerSource,
	type LockoutPolicy,
	type Lockouts,
	lockoutProblem,
	lockouts,
	type Reserved,
	rateLimit,
	requestsPerSource,
} from "../src/contract.ts";
import { lockoutSpace } from "../src/lockout.ts";
import rateLimitModule from "../src/module.ts";
import { partitionOf } from "../src/partition.ts";

const start = 1_800_000_000_000;
let now = start;
let stop = async () => {};
afterEach(async () => {
	now = start;
	await stop();
	stop = async () => {};
});
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

async function boot() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [rateLimitModule, simulated.module, auditStandIn().module],
		config: kernelConfig(),
		runtime,
	});
	return {
		simulated,
		limits: app.get(rateLimit),
		lockouts: app.get(lockouts),
		attempts: app.get(attemptLimit),
		store: app.get(store),
	};
}

it("allows up to the limit per key and window, then says how long to wait", async () => {
	const { limits } = await boot();
	const window = { limit: 2, ms: 60_000 };
	expect(await limits.hit("w1", "a", window)).toEqual({ kind: "allowed" });
	expect(await limits.hit("w1", "a", window)).toEqual({ kind: "allowed" });
	const limited = await limits.hit("w1", "a", window);
	expect(limited.kind).toBe("limited");
	expect(limited).toEqual({ kind: "limited", retryAfterMs: 60_000 });
	expect(await limits.hit("w1", "b", window)).toEqual({ kind: "allowed" });
	expect(await limits.hit("w2", "a", window)).toEqual({ kind: "allowed" });
	now += 60_001;
	expect(await limits.hit("w1", "a", window)).toEqual({ kind: "allowed" });
});

it("takes any key, however long, and is unavailable when it cannot count", async () => {
	const { simulated, limits } = await boot();
	expect(await limits.hit("w1", "x".repeat(10_000), { limit: 1, ms: 1000 })).toEqual({
		kind: "allowed",
	});
	simulated.unreachable(true);
	await expect(limits.hit("w1", "a", { limit: 1, ms: 1000 })).rejects.toSatisfy(isUnavailable);
});

it("keeps names and keys apart however they are named, inherited property names included", async () => {
	const { limits, lockouts: l } = await boot();
	const window = { limit: 1, ms: 60_000 };
	expect(await limits.hit("constructor", "__proto__", window)).toEqual({ kind: "allowed" });
	expect(await limits.hit("__proto__", "constructor", window)).toEqual({ kind: "allowed" });
	expect((await limits.hit("constructor", "__proto__", window)).kind).toBe("limited");
	await l.failed("toString", "__proto__", { ...policy, threshold: 1 });
	expect((await l.check("toString", "__proto__", { ...policy, threshold: 1 })).kind).toBe("held");
	expect(await l.check("__proto__", "toString", { ...policy, threshold: 1 })).toEqual({
		kind: "open",
	});
});

/** The reservation of an open answer; a held one fails the test. */
function opened(reserved: Reserved): number {
	if (reserved.kind !== "open") throw new Error(`held: ${JSON.stringify(reserved)}`);
	return reserved.reservation;
}

const policy: LockoutPolicy = {
	threshold: 3,
	backoffMs: 1000,
	maxBackoffMs: 4000,
	budget: 6,
	budgetWindowMs: 86_400_000,
	hardLimit: 10,
	memoryMs: 60_000,
};

it("holds a key after a run of failures, doubling the hold to a ceiling, and a success ends the run", async () => {
	const { lockouts: l } = await boot();
	// Room in the budget for every failure here.
	const roomy: LockoutPolicy = { ...policy, budget: 10 };
	expect(await l.failed("l1", "k1", roomy)).toEqual({ kind: "open" });
	expect(await l.failed("l1", "k1", roomy)).toEqual({ kind: "open" });
	expect(await l.failed("l1", "k1", roomy)).toEqual({
		kind: "held",
		hold: "backoff",
		retryAfterMs: 1000,
	});
	expect((await l.check("l1", "k1", roomy)).kind).toBe("held");
	expect(await l.check("l1", "k2", roomy)).toEqual({ kind: "open" });
	now += 999;
	expect((await l.check("l1", "k1", roomy)).kind).toBe("held");
	now += 1;
	expect(await l.check("l1", "k1", roomy)).toEqual({ kind: "open" });
	expect(await l.failed("l1", "k1", roomy)).toEqual({
		kind: "held",
		hold: "backoff",
		retryAfterMs: 2000,
	});
	now += 2001;
	await l.failed("l1", "k1", roomy);
	now += 4001;
	expect(await l.failed("l1", "k1", roomy)).toEqual({
		kind: "held",
		hold: "backoff",
		retryAfterMs: 4000,
	});
	now += 4001;
	await l.succeeded("l1", "k1", roomy);
	expect(await l.failed("l1", "k1", roomy)).toEqual({ kind: "open" });
});

it("holds a key that spent its budget until the oldest failure leaves the caller's window, even after forgetting the run", async () => {
	const { lockouts: l } = await boot();
	const started = now;
	for (let i = 0; i < 6; i++) {
		await l.failed("l1", "k3", policy);
		await l.succeeded("l1", "k3", policy);
		now += 61_000;
	}
	const held = await l.check("l1", "k3", policy);
	expect(held.kind === "held" && held.hold).toBe("budget");
	// A failure while held still counts, and the oldest of the last six sets the wait.
	await l.failed("l1", "k3", policy);
	expect(await l.check("l1", "k3", policy)).toEqual({
		kind: "held",
		hold: "budget",
		retryAfterMs: started + 61_000 + 86_400_000 - now,
	});
	now = started + 61_000 + 86_400_000 - 1;
	expect((await l.check("l1", "k3", policy)).kind).toBe("held");
	now = started + 2 * 61_000 + 86_400_000 + 1;
	expect(await l.check("l1", "k3", policy)).toEqual({ kind: "open" });
});

it("fixes the hold at the hard limit until it is released, and is unavailable when it cannot tell", async () => {
	const { simulated, lockouts: l } = await boot();
	const hard: LockoutPolicy = {
		...policy,
		budget: 10,
		hardLimit: 10,
		maxBackoffMs: 1000,
		backoffMs: 1000,
		threshold: 10,
		memoryMs: 1000,
	};
	for (let i = 0; i < 9; i++) await l.failed("l1", "k4", hard);
	expect(await l.failed("l1", "k4", hard)).toEqual({ kind: "held", hold: "hard" });
	now += 30 * 86_400_000;
	expect(await l.check("l1", "k4", hard)).toEqual({ kind: "held", hold: "hard" });
	await l.releaseUnder("l1", "k4", hard, { kind: "whole" });
	expect(await l.check("l1", "k4", hard)).toEqual({ kind: "open" });
	simulated.unreachable(true);
	await expect(l.check("l1", "k4", hard)).rejects.toSatisfy(isUnavailable);
	simulated.unreachable(false);
});

it("is unavailable when other writers keep changing a key's lockout before each count lands", async () => {
	const { simulated, lockouts: l, store } = await boot();
	await l.failed("l1", "busy", policy);
	const held = { space: lockoutSpace, partition: partitionOf("l1", "busy"), name: "lockout" };
	// One race for each of the store's eight attempts.
	const contend = (times: number) => {
		if (times === 0) return;
		simulated.beforeNext("replaceIf", lockoutSpace.name, async () => {
			const { entry } = await store.get(held);
			const expiry = { expiry: { kind: "after", ms: 60_000 } } as const;
			await (entry
				? store.replaceIf(held, entry.version, entry.value, expiry)
				: store.putIfAbsent(held, {}, expiry));
			contend(times - 1);
		});
	};
	contend(8);
	await expect(l.failed("l1", "busy", policy)).rejects.toSatisfy(isUnavailable);
});

it("judges a lockout policy's shape", () => {
	expect(lockoutProblem(policy)).toBeUndefined();
	expect(lockoutProblem({ ...policy, threshold: 0 })).toBeDefined();
	expect(lockoutProblem({ ...policy, maxBackoffMs: 500 })).toBeDefined();
	expect(lockoutProblem({ ...policy, hardLimit: 5 })).toBeDefined();
	expect(lockoutProblem({ ...policy, memoryMs: 1000 })).toBeDefined();
	expect(lockoutProblem({ ...policy, budgetWindowMs: 0 })).toBeDefined();
	expect(lockoutProblem({ ...policy, backoffMs: 1.5 })).toBeDefined();
	expect(lockoutProblem({ ...policy, budget: 2 })).toBeDefined();
});

it("reserves an attempt before a guess as one write, so concurrent guesses cannot pass the limit, and hands it back on success", async () => {
	const { lockouts: l } = await boot();
	const tight: LockoutPolicy = { ...policy, threshold: 2, budget: 6 };
	const answers = await Promise.all(Array.from({ length: 5 }, () => l.reserve("l1", "k5", tight)));
	expect(answers.filter((a) => a.kind === "open")).toHaveLength(2);
	expect(answers.filter((a) => a.kind === "held")).toHaveLength(3);
	const fresh = await boot();
	for (let i = 0; i < 6; i++) {
		const reserved = await fresh.lockouts.reserve("l1", "k6", tight);
		expect(reserved.kind).toBe("open");
		await fresh.lockouts.succeeded("l1", "k6", tight, opened(reserved));
	}
	expect(await fresh.lockouts.check("l1", "k6", tight)).toEqual({ kind: "open" });
});

it("tells the reservation that starts a hold, and no other", async () => {
	const { lockouts: l } = await boot();
	const holdsOf = async (key: string, of: LockoutPolicy) => {
		const reserved = await l.reserve("l1", key, of);
		return reserved.kind === "open" ? (reserved.holds ?? "none") : "held";
	};
	const run = async (key: string, of: LockoutPolicy, times: number) => {
		const told: string[] = [];
		for (let i = 0; i < times; i++) told.push(await holdsOf(key, of));
		return told;
	};
	expect(await run("backoff", policy, 4)).toEqual(["none", "none", "backoff", "held"]);
	// A success ends the run but keeps the failure against the budget.
	const budgeted: LockoutPolicy = { ...policy, threshold: 2, budget: 2, hardLimit: 3 };
	await l.failed("l1", "budget", budgeted);
	await l.succeeded("l1", "budget", budgeted);
	expect(await run("budget", budgeted, 2)).toEqual(["budget", "held"]);
	const hard: LockoutPolicy = { ...policy, threshold: 1, budget: 1, hardLimit: 1 };
	expect(await run("hard", hard, 2)).toEqual(["hard", "held"]);
});

it("never fixes a hold for an attempt that is handed back as a success, but does for one that is not", async () => {
	const { lockouts: l } = await boot();
	const edge: LockoutPolicy = { ...policy, threshold: 1, budget: 3, hardLimit: 3 };
	const reserveOpen = async (key: string) => {
		const reservation = opened(await l.reserve("l1", key, edge));
		// Past the hold the last attempt may have left, so the next one is open.
		now += 4001;
		return reservation;
	};
	for (const key of ["k7", "k8"]) {
		await reserveOpen(key);
		await reserveOpen(key);
	}
	await l.succeeded("l1", "k7", edge, await reserveOpen("k7"));
	expect(await l.check("l1", "k7", edge)).toEqual({ kind: "open" });
	await reserveOpen("k8");
	await l.succeeded("l1", "k8", edge);
	expect(await l.check("l1", "k8", edge)).toEqual({ kind: "held", hold: "hard" });
});

it("keeps a fixed hold when an attempt other than the one that fixed it is handed back", async () => {
	const { lockouts: l } = await boot();
	const two: LockoutPolicy = { ...policy, threshold: 2, budget: 2, hardLimit: 2 };
	const first = await l.reserve("l1", "k11", two);
	const fixing = await l.reserve("l1", "k11", two);
	expect(fixing).toMatchObject({ kind: "open", holds: "hard" });
	if (first.kind !== "open") throw new Error("held");
	await l.succeeded("l1", "k11", two, first.reservation);
	expect(await l.check("l1", "k11", two)).toEqual({ kind: "held", hold: "hard" });
});

it("hands back an attempt never judged without ending the run, once", async () => {
	const { lockouts: l } = await boot();
	const one: LockoutPolicy = { ...policy, threshold: 2, budget: 3, hardLimit: 3 };
	await l.failed("l1", "k9", one);
	const reserved = await l.reserve("l1", "k9", one);
	const reservation = opened(reserved);
	expect((await l.check("l1", "k9", one)).kind).toBe("held");
	await l.abandoned("l1", "k9", one, reservation);
	expect(await l.check("l1", "k9", one)).toEqual({ kind: "open" });
	await l.abandoned("l1", "k9", one, reservation);
	now += 1;
	expect((await l.failed("l1", "k9", one)).kind).toBe("held");
	now += 4001;
	const last = await l.reserve("l1", "k9", one);
	expect(await l.check("l1", "k9", one)).toEqual({ kind: "held", hold: "hard" });
	await l.abandoned("l1", "k9", one, opened(last));
	expect((await l.check("l1", "k9", one)).kind).toBe("open");
});

it("never names two attempts alike, even once an earlier one was handed back", async () => {
	const { lockouts: l } = await boot();
	const first = await l.reserve("l1", "k10", policy);
	const r1 = opened(first);
	await l.succeeded("l1", "k10", policy, r1);
	const second = await l.reserve("l1", "k10", policy);
	const r2 = opened(second);
	expect(r2).not.toBe(r1);
	await l.abandoned("l1", "k10", policy, r1);
	await l.failed("l1", "k10", policy);
	expect((await l.failed("l1", "k10", policy)).kind).toBe("held");
});

/** Fails `times` attempts at a key, a millisecond apart. */
async function fail(l: Lockouts, key: string, of: LockoutPolicy, times: number) {
	for (let i = 0; i < times; i++) {
		await l.failed("l1", key, of);
		now += 1;
	}
}

const fixing: LockoutPolicy = {
	...policy,
	threshold: 10,
	budget: 10,
	hardLimit: 10,
	backoffMs: 1000,
	maxBackoffMs: 1000,
	memoryMs: 1000,
};
const once = (id: string) => ({ id, keepMs: 60_000 });

describe("releasing a lockout under terms", () => {
	it("stands on the oldest failure the budget counts and when the hold was fixed", async () => {
		const { lockouts: l } = await boot();
		expect(await l.standing("l1", "s1", fixing)).toEqual({});
		await fail(l, "s1", fixing, 3);
		expect(await l.standing("l1", "s1", fixing)).toEqual({ firstFailureAt: start });
		await fail(l, "s1", fixing, 7);
		expect(await l.standing("l1", "s1", fixing)).toEqual({
			firstFailureAt: start,
			fixedAt: start + 9,
		});
		now = start + fixing.budgetWindowMs;
		expect(await l.standing("l1", "s1", fixing)).toEqual({
			firstFailureAt: start + 1,
			fixedAt: start + 9,
		});
	});

	it("forgives the budget and the run, and lifts a fixed hold, each only on its own term", async () => {
		const { lockouts: l } = await boot();
		await fail(l, "r1", policy, 4);
		const r1 = await l.standing("l1", "r1", policy);
		expect(
			await l.releaseUnder("l1", "r1", policy, { kind: "checked", once: once("a"), forgive: r1 }),
		).toEqual({
			kind: "released",
			generation: 1,
			cleared: { budget: true, run: true, hard: false },
		});
		expect(await l.check("l1", "r1", policy)).toEqual({ kind: "open" });
		// The budget goes, but the run stays while the fixed hold does.
		await fail(l, "r2", fixing, 10);
		const r2 = await l.standing("l1", "r2", fixing);
		expect(
			await l.releaseUnder("l1", "r2", fixing, { kind: "checked", once: once("b"), forgive: r2 }),
		).toEqual({
			kind: "released",
			generation: 1,
			cleared: { budget: true, run: false, hard: false },
			fixedAt: r2.fixedAt,
		});
		expect(await l.check("l1", "r2", fixing)).toEqual({ kind: "held", hold: "hard" });
		// Lifting the hold ends its run; a budget not forgiven still holds.
		await fail(l, "r3", fixing, 10);
		const r3 = await l.standing("l1", "r3", fixing);
		expect(
			await l.releaseUnder("l1", "r3", fixing, {
				kind: "checked",
				once: once("c"),
				// Not r3's first failure: the budget stays.
				forgive: { firstFailureAt: start },
				lift: { fixedAt: r3.fixedAt ?? 0 },
			}),
		).toEqual({
			kind: "released",
			generation: 1,
			cleared: { budget: false, run: true, hard: true },
		});
		expect(await l.check("l1", "r3", fixing)).toMatchObject({ kind: "held", hold: "budget" });
		await fail(l, "r4", fixing, 10);
		const r4 = await l.standing("l1", "r4", fixing);
		expect(
			await l.releaseUnder("l1", "r4", fixing, {
				kind: "checked",
				once: once("d"),
				forgive: r4,
				lift: { fixedAt: r4.fixedAt ?? 0 },
			}),
		).toEqual({
			kind: "released",
			generation: 1,
			cleared: { budget: true, run: true, hard: true },
		});
		expect(await l.check("l1", "r4", fixing)).toEqual({ kind: "open" });
		// A key that counts nothing is forgiven too.
		expect(
			await l.releaseUnder("l1", "r5", policy, { kind: "checked", once: once("e"), forgive: {} }),
		).toMatchObject({ kind: "released", cleared: { budget: true, run: true, hard: false } });
	});

	it("applies no term once the key changed since it was read, and spends no id on that", async () => {
		const { lockouts: l } = await boot();
		const read = await l.standing("l1", "c1", fixing);
		await fail(l, "c1", fixing, 10);
		const old = await l.standing("l1", "c1", fixing);
		expect(
			await l.releaseUnder("l1", "c1", fixing, { kind: "checked", once: once("x"), forgive: read }),
		).toEqual({ kind: "unchanged", fixedAt: old.fixedAt });
		// The hold is fixed again after another release, at another time.
		await l.releaseUnder("l1", "c1", fixing, { kind: "whole" });
		await fail(l, "c1", fixing, 10);
		expect(
			await l.releaseUnder("l1", "c1", fixing, {
				kind: "checked",
				once: once("x"),
				lift: { fixedAt: old.fixedAt ?? 0 },
			}),
		).toMatchObject({ kind: "unchanged" });
		expect(await l.check("l1", "c1", fixing)).toEqual({ kind: "held", hold: "hard" });
		const current = await l.standing("l1", "c1", fixing);
		expect(
			await l.releaseUnder("l1", "c1", fixing, {
				kind: "checked",
				once: once("x"),
				forgive: current,
				lift: { fixedAt: current.fixedAt ?? 0 },
			}),
		).toMatchObject({ kind: "released", generation: 2 });
	});

	it("applies a release once while its id is kept, then as a new one", async () => {
		const { lockouts: l } = await boot();
		await fail(l, "o1", policy, 2);
		const terms = { kind: "checked", once: once("y"), forgive: { firstFailureAt: start } } as const;
		expect(await l.releaseUnder("l1", "o1", policy, terms)).toMatchObject({
			kind: "released",
			generation: 1,
		});
		await fail(l, "o1", policy, 1);
		const counted = await l.standing("l1", "o1", policy);
		const again = { ...terms, forgive: counted };
		expect(await l.releaseUnder("l1", "o1", policy, again)).toEqual({
			kind: "already",
			generation: 1,
		});
		expect(await l.standing("l1", "o1", policy)).toEqual(counted);
		now += 60_000;
		expect(await l.releaseUnder("l1", "o1", policy, again)).toMatchObject({
			kind: "released",
			generation: 2,
		});
	});

	it("answers what it judged on the state it wrote, when a failure lands between its read and its write", async () => {
		const { simulated, lockouts: l } = await boot();
		await fail(l, "w1", fixing, 10);
		const read = await l.standing("l1", "w1", fixing);
		// Another request lifts the hold in place, as a release by another proof would, just before this write.
		simulated.beforeNext("replaceIf", lockoutSpace.name, async () => {
			await l.releaseUnder("l1", "w1", fixing, { kind: "whole" });
		});
		const terms = {
			kind: "checked",
			once: once("w"),
			forgive: read,
			lift: { fixedAt: read.fixedAt ?? 0 },
		} as const;
		expect(await l.releaseUnder("l1", "w1", fixing, terms)).toEqual({ kind: "unchanged" });
		expect(await l.check("l1", "w1", fixing)).toEqual({ kind: "open" });
	});

	it("counts every release in the generation, a whole one too, and keeps that count past every window", async () => {
		const { lockouts: l } = await boot();
		await fail(l, "g1", fixing, 10);
		expect(await l.releaseUnder("l1", "g1", fixing, { kind: "whole" })).toEqual({
			kind: "released",
			generation: 1,
			cleared: { budget: true, run: true, hard: true },
		});
		expect(await l.check("l1", "g1", fixing)).toEqual({ kind: "open" });
		const month = 30 * 86_400_000;
		now += month;
		await l.failed("l1", "g1", fixing);
		now += month;
		// A hold fixed and handed back by the attempt that fixed it is written too.
		const single: LockoutPolicy = { ...fixing, threshold: 1, budget: 1, hardLimit: 1 };
		await l.succeeded("l1", "g1", single, opened(await l.reserve("l1", "g1", single)));
		now += month;
		expect(await l.releaseUnder("l1", "g1", fixing, { kind: "whole" })).toMatchObject({
			generation: 2,
		});
		now += month;
		expect(
			await l.releaseUnder("l1", "g1", fixing, { kind: "checked", once: once("z"), forgive: {} }),
		).toMatchObject({ kind: "released", generation: 3 });
	});
});

const window = { limit: 2, ms: 60_000 };
/** Routes counted by each policy under the name `test`, two to a window. */
const routed = defineModule({ name: "routed", takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/attempts",
		changesState: false,
		uses: [use(attemptsPerSource, { name: "test", window })],
		handle: () => ({ status: 204 }),
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/requests",
		changesState: false,
		uses: [use(requestsPerSource, { name: "test", window })],
		handle: () => ({ status: 204 }),
	})),
]);

/** The routes behind http, trusting the local proxy, with what each request answers. */
async function serving(section?: Record<string, unknown>) {
	const recorded = recordingLog();
	const simulated = simulatedStore();
	const audit = auditStandIn();
	const app = await assemble({
		modules: [http, audit.module, metricsModule, rateLimitModule, simulated.module, routed],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"] }),
			...(section ? { "rate-limit": section } : {}),
		},
		runtime: quietRuntime({ ...runtime, log: recorded.log }),
	});
	await app.start();
	stop = () => app.stop(1000);
	const from = (path: string, address?: string) =>
		fetch(`http://127.0.0.1:${app.get(listening).port()}${path}`, {
			headers: address ? { "x-forwarded-for": address } : {},
		});
	const statuses = async (path: string, address: string, times: number) => {
		const seen: number[] = [];
		for (let i = 0; i < times; i++) seen.push((await from(path, address)).status);
		return seen;
	};
	/** The uncounted series, by limit, as metrics reads them. */
	const uncounted = () =>
		app
			.get(metrics)
			.read()
			.find((reading) => reading.name === "auth_rate_limit_uncounted_total")?.series ?? [];
	return { app, simulated, events: audit.events, recorded, from, statuses, uncounted };
}

const limitedAnswer = async (res: Response) => [
	res.status,
	res.headers.get("retry-after"),
	res.headers.get("cache-control"),
	await res.json(),
];

describe("the policies for routes", () => {
	it("limits attempts per IPv4 address and per IPv6 /64, answering 429 with the wait", async () => {
		const { from, statuses } = await serving();
		expect(await statuses("/attempts", "198.51.100.1", 2)).toEqual([204, 204]);
		expect(await limitedAnswer(await from("/attempts", "198.51.100.1"))).toEqual([
			429,
			"60",
			"no-store",
			{ error: "too_many_attempts" },
		]);
		expect(await statuses("/attempts", "198.51.100.2", 1)).toEqual([204]);
		const v6 = [
			...(await statuses("/attempts", "2001:db8::1", 2)),
			...(await statuses("/attempts", "2001:db8::2", 1)),
		];
		expect(v6).toEqual([204, 204, 429]);
		expect(await statuses("/attempts", "2001:db8:0:1::1", 1)).toEqual([204]);
	});

	it("refuses a source it cannot tell with 503, logged as a deployment error", async () => {
		const { from, recorded } = await serving();
		for (const path of ["/attempts", "/requests"]) {
			const unknown = await from(path);
			expect([unknown.status, await unknown.json()], path).toEqual([
				503,
				{ error: "service_unavailable" },
			]);
		}
		const errors = recorded.lines().filter((line) => line.level === "error");
		expect(errors.map((line) => line.event)).toEqual([
			"rate-limit.source_undetermined",
			"rate-limit.source_undetermined",
		]);
	});

	it("counts attempts apart from rate limits, and through a failover", async () => {
		const { app, simulated, statuses } = await serving();
		expect(await statuses("/attempts", "198.51.100.4", 1)).toEqual([204]);
		expect(await app.get(rateLimit).hit("test", "198.51.100.4", { limit: 1, ms: 60_000 })).toEqual({
			kind: "allowed",
		});
		await simulated.failover();
		expect(await statuses("/attempts", "198.51.100.4", 2)).toEqual([204, 429]);
	});

	it("limits requests per source apart from attempts, answering 429 with the wait", async () => {
		const { from, statuses } = await serving();
		expect(await statuses("/requests", "198.51.100.1", 2)).toEqual([204, 204]);
		expect(await limitedAnswer(await from("/requests", "198.51.100.1"))).toEqual([
			429,
			"60",
			"no-store",
			{ error: "rate_limited" },
		]);
		expect(await statuses("/requests", "198.51.100.2", 1)).toEqual([204]);
		expect(await statuses("/attempts", "198.51.100.1", 2)).toEqual([204, 204]);
	});

	it("refuses a request and an attempt with 503 when it cannot count, by default, recording and counting both", async () => {
		const { from, simulated, events, uncounted } = await serving();
		expect(events).toEqual([]);
		simulated.unreachable(true);
		for (const path of ["/requests", "/attempts"]) {
			const refused = await from(path, "198.51.100.3");
			expect([refused.status, await refused.json()], path).toEqual([
				503,
				{ error: "service_unavailable" },
			]);
		}
		simulated.unreachable(false);
		expect(events.map((e) => [e.kind, e.at, e.attributes])).toEqual([
			[
				"rate_limit.unavailable",
				now,
				{ name: "test", limit: "requests", source: "198.51.100.3", outcome: "refused" },
			],
			[
				"rate_limit.unavailable",
				now,
				{ name: "test", limit: "attempts", source: "198.51.100.3", outcome: "refused" },
			],
		]);
		expect(uncounted()).toEqual([
			{ labels: { limit: "requests" }, value: 1 },
			{ labels: { limit: "attempts" }, value: 1 },
		]);
	});

	it("lets a request by when it cannot count where the section says open, never an attempt", async () => {
		const { from, simulated, events, uncounted } = await serving({ "fail-mode": "open" });
		simulated.unreachable(true);
		expect((await from("/requests", "198.51.100.3")).status).toBe(204);
		const attempt = await from("/attempts", "198.51.100.3");
		expect([attempt.status, await attempt.json()]).toEqual([503, { error: "service_unavailable" }]);
		simulated.unreachable(false);
		expect(events.map((e) => [e.attributes?.limit, e.attributes?.outcome])).toEqual([
			["requests", "let_through"],
			["attempts", "refused"],
		]);
		expect(uncounted()).toEqual([
			{ labels: { limit: "requests" }, value: 1 },
			{ labels: { limit: "attempts" }, value: 1 },
		]);
	});

	it("counts each use it cannot count once, by its limit, called by a handler as by a policy", async () => {
		const { app, simulated, events, uncounted } = await serving();
		simulated.unreachable(true);
		await expect(app.get(rateLimit).hit("own", "k", window)).rejects.toSatisfy(isUnavailable);
		await expect(app.get(attemptLimit).hit("own", "k", window)).rejects.toSatisfy(isUnavailable);
		await expect(app.get(attemptLimit).hit("own", "k", window)).rejects.toSatisfy(isUnavailable);
		simulated.unreachable(false);
		// Another failure is thrown as it is, and counted as nothing.
		simulated.beforeNext("count", "rate-limit.windows", () => {
			throw new Error("broken");
		});
		await expect(app.get(rateLimit).hit("own", "k", window)).rejects.toThrow("broken");
		expect(events).toEqual([]);
		expect(uncounted()).toEqual([
			{ labels: { limit: "requests" }, value: 1 },
			{ labels: { limit: "attempts" }, value: 2 },
		]);
	});

	it("refuses boot on a fail mode other than open or closed", async () => {
		await expect(serving({ "fail-mode": "half" })).rejects.toBeInstanceOf(BootRefused);
	});
});

it("counts attempts by any key in counts kept through a failover, apart from rate limits, and is unavailable when it cannot count", async () => {
	const { simulated, attempts, limits } = await boot();
	expect(await attempts.hit("guess", "alice", window)).toEqual({ kind: "allowed" });
	expect(await limits.hit("guess", "alice", window)).toEqual({ kind: "allowed" });
	await simulated.failover();
	expect(await attempts.hit("guess", "alice", window)).toEqual({ kind: "allowed" });
	expect((await attempts.hit("guess", "alice", window)).kind).toBe("limited");
	expect(await attempts.hit("guess", "bob", window)).toEqual({ kind: "allowed" });
	simulated.unreachable(true);
	await expect(attempts.hit("guess", "carol", window)).rejects.toSatisfy(isUnavailable);
});

it("takes every handle its takes name", async () => {
	const modules = [rateLimitModule, simulatedStore().module, auditStandIn().module];
	expect(await takesUnused({ modules, config: kernelConfig() })).toEqual({});
});
