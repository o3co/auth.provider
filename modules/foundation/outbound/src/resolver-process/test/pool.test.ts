import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type HelperProcess, poolLimits, ResolutionFailed, resolverPool } from "../contract.ts";

/** A helper the test drives: what it was sent, whether it was killed or held, and its events. */
class Fake implements HelperProcess {
	readonly sent: Record<string, unknown>[] = [];
	killed = 0;
	held = false;
	/** A fake that ignores the kill: it never exits. */
	stuck = false;
	readonly listeners = new Map<string, ((...args: never[]) => void)[]>();
	readonly gen: number;
	readonly threads: number;
	readonly pid: number | undefined;
	/** `pid` null: a process never started. */
	constructor(gen: number, threads: number, pid: number | null = 1000 + gen) {
		this.gen = gen;
		this.threads = threads;
		this.pid = pid ?? undefined;
	}
	send(message: object) {
		this.sent.push(message as Record<string, unknown>);
	}
	kill() {
		this.killed += 1;
		if (!this.stuck) queueMicrotask(() => this.emit("exit"));
	}
	hold(held: boolean) {
		this.held = held;
	}
	on(event: string, listener: (...args: never[]) => void) {
		this.listeners.set(event, [...(this.listeners.get(event) ?? []), listener]);
	}
	emit(event: string, ...args: unknown[]) {
		const listeners = this.listeners.get(event) ?? [];
		// As a ChildProcess: an error no one listens for is thrown.
		if (event === "error" && listeners.length === 0) throw args[0];
		for (const l of listeners) (l as (...a: unknown[]) => void)(...args);
	}
	ready() {
		this.emit("message", { gen: this.gen, ready: true });
	}
	/** Answers the lookup it was sent `at` (0 the first) with this message. */
	answer(at: number, message: Record<string, unknown>) {
		this.emit("message", { gen: this.gen, id: this.sent[at]?.id, ...message });
	}
}

function harness(size = 2) {
	const started: Fake[] = [];
	const warned: [string, Record<string, unknown>][] = [];
	let failNext = false;
	const pool = resolverPool({
		pool: "own",
		size,
		warn: (event, fields) => warned.push([event, fields]),
		now: () => Date.now(),
		start: (gen, threads) => {
			if (failNext) throw new Error("no process");
			const f = new Fake(gen, threads);
			started.push(f);
			return f;
		},
	});
	const latest = () => started.at(-1) as Fake;
	const ready = async () => {
		const starting = pool.start();
		latest().ready();
		await starting;
	};
	const settled = async () => {
		await vi.advanceTimersByTimeAsync(0);
	};
	return {
		pool,
		started,
		warned,
		latest,
		ready,
		settled,
		failSpawns: () => {
			failNext = true;
		},
	};
}

const reason = (promise: Promise<unknown>) =>
	promise.then(
		() => "answered",
		(error) => (error instanceof ResolutionFailed ? error.reason : String(error)),
	);

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("a pool's lookups", () => {
	it("starts its helper with the pool's threads, answers a lookup, and gives its place back", async () => {
		const h = harness(1);
		await h.ready();
		expect(h.latest().threads).toBe(1);
		const job = h.pool.run("collector", 4);
		expect(h.latest().sent).toEqual([{ id: 1, name: "collector", family: 4 }]);
		expect(h.pool.run("other")).toBeUndefined();
		h.latest().answer(0, { addresses: ["10.0.0.1"] });
		await expect(job?.answer).resolves.toEqual(["10.0.0.1"]);
		expect(h.pool.run("other")).toBeDefined();
	});

	it("fails a lookup the name's answer refuses, keeping the helper", async () => {
		const h = harness();
		await h.ready();
		const job = h.pool.run("nowhere");
		h.latest().answer(0, { code: "ENOTFOUND" });
		expect(await reason(job?.answer as Promise<unknown>)).toBe("not-found");
		expect(h.latest().killed).toBe(0);
	});

	it("drops a lookup answered with more addresses than it takes, keeping the helper", async () => {
		const h = harness();
		await h.ready();
		const job = h.pool.run("many");
		const many = Array.from(
			{ length: poolLimits.maxAddresses + 1 },
			(_, i) => `10.0.${i >> 8}.${i & 255}`,
		);
		h.latest().answer(0, { addresses: many });
		expect(await reason(job?.answer as Promise<unknown>)).toBe("too-many");
		expect(h.latest().killed).toBe(0);
		expect(h.pool.run("next")).toBeDefined();
	});

	it("keeps the parent alive while someone waits on a lookup, and lets it go otherwise", async () => {
		const h = harness();
		await h.ready();
		expect(h.latest().held).toBe(false);
		const job = h.pool.run("a");
		expect(h.latest().held).toBe(true);
		h.latest().answer(0, { addresses: ["10.0.0.1"] });
		await job?.answer;
		expect(h.latest().held).toBe(false);
	});
});

describe("a helper whose lookups no one waits on", () => {
	it("is ended once all its running lookups are left, its places held until it is gone, then started again", async () => {
		const h = harness(2);
		await h.ready();
		const first = h.latest();
		const a = h.pool.run("a");
		const b = h.pool.run("b");
		a?.unwant();
		expect(first.killed).toBe(0);
		// Wanted again before the other is left: kept.
		expect(a?.want()).toBe(true);
		b?.unwant();
		expect(first.killed).toBe(0);
		a?.unwant();
		expect(first.killed).toBe(1);
		expect(first.held).toBe(false);
		// Being ended: no one may wait on it again, and no lookup is taken.
		expect(a?.want()).toBe(false);
		expect(h.pool.run("c")).toBeUndefined();
		await h.settled();
		expect(h.started).toHaveLength(2);
		h.latest().ready();
		expect(h.pool.run("c")).toBeDefined();
		expect(h.warned).toEqual([]);
	});

	it("is ended once the last lookup waited on is answered, the others left", async () => {
		const h = harness(2);
		await h.ready();
		const left = h.pool.run("left");
		h.pool.run("waited");
		left?.unwant();
		expect(h.latest().killed).toBe(0);
		h.latest().answer(1, { addresses: ["10.0.0.1"] });
		expect(h.latest().killed).toBe(1);
	});

	it("looks again at the helper that replaced one ended before its look again", async () => {
		const h = harness(1);
		await h.ready();
		for (let i = 0; i < poolLimits.abandonRestarts; i++) {
			h.pool.run(`n${i}`)?.unwant();
			await h.settled();
			h.latest().ready();
		}
		// Kept past the window, a look again scheduled; then it dies of its own.
		h.pool.run("left")?.unwant();
		h.latest().emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		h.latest().ready();
		const replacing = h.latest();
		h.pool.run("left again")?.unwant();
		expect(replacing.killed).toBe(0);
		await vi.advanceTimersByTimeAsync(poolLimits.windowMs);
		expect(replacing.killed).toBe(1);
	});

	it("is kept past the window's ends, and looked at again once the window lets one go", async () => {
		const h = harness(1);
		await h.ready();
		for (let i = 0; i < poolLimits.abandonRestarts; i++) {
			h.pool.run(`n${i}`)?.unwant();
			await h.settled();
			h.latest().ready();
		}
		expect(h.started).toHaveLength(poolLimits.abandonRestarts + 1);
		const kept = h.latest();
		h.pool.run("left")?.unwant();
		await h.settled();
		expect(kept.killed).toBe(0);
		expect(h.pool.run("blocked")).toBeUndefined();
		// No answer and no new lookup come; the window frees, and the look again ends it.
		await vi.advanceTimersByTimeAsync(poolLimits.windowMs);
		expect(kept.killed).toBe(1);
		await h.settled();
		h.latest().ready();
		expect(h.pool.run("after")).toBeDefined();
	});

	it("is not ended at the look again where someone waits once more", async () => {
		const h = harness(1);
		await h.ready();
		for (let i = 0; i < poolLimits.abandonRestarts; i++) {
			h.pool.run(`n${i}`)?.unwant();
			await h.settled();
			h.latest().ready();
		}
		const kept = h.latest();
		const job = h.pool.run("left");
		job?.unwant();
		expect(job?.want()).toBe(true);
		await vi.advanceTimersByTimeAsync(poolLimits.windowMs);
		expect(kept.killed).toBe(0);
	});
});

describe("a helper that fails", () => {
	const broken: [string, Record<string, unknown>][] = [
		["another generation", { gen: 99 }],
		["an unknown lookup", { id: 99, addresses: ["10.0.0.1"] }],
		["both shapes", { addresses: ["10.0.0.1"], code: "ENOTFOUND" }],
		["neither shape", {}],
		["a code out of range", { code: "EVIL" }],
		["no address", { addresses: [] }],
		["not an address", { addresses: ["collector.internal"] }],
		["an IPv6 address for IPv4 alone", { addresses: ["::1"] }],
	];
	for (const [what, message] of broken) {
		it(`is isolated on ${what}: its lookups fail, its places held until it is gone`, async () => {
			const h = harness(1);
			await h.ready();
			const first = h.latest();
			const job = h.pool.run("collector", 4);
			first.emit("message", { gen: first.gen, id: first.sent[0]?.id, ...message });
			expect(first.killed).toBe(1);
			expect(await reason(job?.answer as Promise<unknown>)).toBe("fault");
			expect(h.pool.run("other")).toBeUndefined();
			expect(h.warned).toEqual([["outbound.resolver_fault", { pool: "own", reason: "answer" }]]);
			await h.settled();
			// Started again after the backoff.
			expect(h.started).toHaveLength(1);
			await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
			expect(h.started).toHaveLength(2);
		});
	}

	it("is isolated when its channel drops, and dead only once its exit is seen", async () => {
		const h = harness(1);
		await h.ready();
		const first = h.latest();
		first.stuck = true;
		h.pool.run("a");
		first.emit("disconnect");
		expect(first.killed).toBe(1);
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs * 10);
		expect(h.started).toHaveLength(1);
		expect(h.pool.run("b")).toBeUndefined();
		first.emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		expect(h.started).toHaveLength(2);
	});

	it("holds its places while it never exits, and warns that it is stuck again and again", async () => {
		const h = harness(1);
		await h.ready();
		const first = h.latest();
		first.stuck = true;
		h.pool.run("a");
		first.answer(0, { code: "EVIL" });
		await vi.advanceTimersByTimeAsync(poolLimits.stuckMs * 3);
		expect(h.warned.filter(([event]) => event === "outbound.resolver_stuck")).toHaveLength(3);
		expect(h.pool.run("b")).toBeUndefined();
		expect(h.started).toHaveLength(1);
	});

	it("is started again on an exit of its own, the backoff doubling, and back to its first after an answer", async () => {
		const h = harness(1);
		await h.ready();
		h.latest().emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		h.latest().ready();
		h.latest().emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		expect(h.started).toHaveLength(2);
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		expect(h.started).toHaveLength(3);
		h.latest().ready();
		const job = h.pool.run("a");
		h.latest().answer(0, { addresses: ["10.0.0.1"] });
		await job?.answer;
		expect(h.warned.at(-1)).toEqual(["outbound.resolver_recovered", { pool: "own" }]);
		h.latest().emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
		expect(h.started).toHaveLength(4);
	});

	it("refuses its lookups at once past the window's faults, warning so, until the window frees", async () => {
		const h = harness(1);
		await h.ready();
		// Each answers once, setting the backoff back to its first, then exits: the window is what stops it.
		for (let i = 0; i <= poolLimits.faultRestarts; i++) {
			const job = h.pool.run(`n${i}`);
			h.latest().answer(0, { addresses: ["10.0.0.1"] });
			await job?.answer;
			h.latest().emit("exit");
			if (i < poolLimits.faultRestarts) {
				await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
				h.latest().ready();
			}
		}
		expect(h.warned).toContainEqual([
			"outbound.resolver_restarts",
			{ pool: "own", restarts: poolLimits.faultRestarts + 1 },
		]);
		expect(await reason(h.pool.run("a")?.answer as Promise<unknown>)).toBe("refusing");
		await vi.advanceTimersByTimeAsync(poolLimits.windowMs);
		h.latest().ready();
		expect(h.pool.run("b")).toBeDefined();
	});

	it("names no name and no address in what it logs", async () => {
		const h = harness(1);
		await h.ready();
		h.pool.run("secret.internal");
		h.latest().answer(0, { addresses: ["not-an-address"] });
		for (const [, fields] of h.warned) {
			expect(Object.keys(fields).every((k) => ["pool", "reason", "restarts"].includes(k))).toBe(
				true,
			);
			expect(JSON.stringify(fields)).not.toMatch(/secret|address/);
		}
	});
});

describe("starting and stopping", () => {
	it("fails the first start for good where the helper is not ready in time, starting nothing again", async () => {
		const h = harness();
		const starting = h.pool.start();
		const failed = reason(starting);
		h.latest().stuck = true;
		await vi.advanceTimersByTimeAsync(poolLimits.readyMs);
		// Killed, its end not yet seen: the parent is held until the start is refused.
		expect(h.latest().killed).toBe(1);
		expect(h.latest().held).toBe(true);
		h.latest().emit("exit");
		await vi.advanceTimersByTimeAsync(poolLimits.readyMs);
		await h.settled();
		expect(await failed).toMatch(/did not start: ready-timeout/);
		await vi.advanceTimersByTimeAsync(poolLimits.maxBackoffMs * 4);
		expect(h.started).toHaveLength(1);
		expect(h.pool.run("a")).toBeUndefined();
	});

	it("takes the error a process never started reports later, and fails the start for good", async () => {
		const unborn: Fake[] = [];
		const pool = resolverPool({
			pool: "own",
			size: 1,
			warn: () => {},
			now: () => Date.now(),
			start: (gen, threads) => {
				const f = new Fake(gen, threads, null);
				unborn.push(f);
				return f;
			},
		});
		const failed = reason(pool.start());
		// As Node does with EAGAIN: the error comes after the start has returned.
		expect(() => unborn[0]?.emit("error", new Error("spawn EAGAIN"))).not.toThrow();
		expect(await failed).toMatch(/did not start: spawn-failed/);
	});

	it("fails the first start for good where no process is started, and none is tried again", async () => {
		const h = harness();
		h.failSpawns();
		expect(await reason(h.pool.start())).toMatch(/did not start: spawn-failed/);
		await vi.advanceTimersByTimeAsync(poolLimits.maxBackoffMs * 4);
		expect(h.started).toHaveLength(0);
	});

	it("holds the parent while a stop waits for the helper's end, through the channel dropping, and is not undone", async () => {
		const h = harness();
		await h.ready();
		const first = h.latest();
		first.stuck = true;
		const job = h.pool.run("a");
		const stopping = h.pool.stop();
		expect(first.killed).toBe(1);
		expect(first.held).toBe(true);
		// The channel drops as the helper dies: still held, no fault, nothing waited on again.
		first.emit("disconnect");
		expect(first.held).toBe(true);
		expect(first.killed).toBe(1);
		expect(job?.want()).toBe(false);
		expect(h.warned).toEqual([]);
		first.emit("exit");
		await stopping;
		await vi.advanceTimersByTimeAsync(poolLimits.maxBackoffMs);
		expect(h.started).toHaveLength(1);
	});

	it("stops any number of times, while starting, ready, or waiting to start again, ending the helper and starting none", async () => {
		const starting = harness();
		const pending = reason(starting.pool.start());
		await starting.pool.stop();
		await starting.pool.stop();
		expect(await pending).toMatch(/stopped/);
		expect(starting.latest().killed).toBe(1);

		const ready = harness();
		await ready.ready();
		const job = ready.pool.run("a");
		await ready.pool.stop();
		expect(await reason(job?.answer as Promise<unknown>)).toBe("stopped");
		expect(ready.warned).toEqual([]);

		const waiting = harness();
		await waiting.ready();
		waiting.latest().emit("exit");
		await waiting.settled();
		await waiting.pool.stop();
		await vi.advanceTimersByTimeAsync(poolLimits.maxBackoffMs);
		expect(waiting.started).toHaveLength(1);
		expect(waiting.pool.run("a")).toBeUndefined();
	});
});

describe("what a pool leaves to its parent", () => {
	it("lets a refused answer no one reads go, never an unhandled rejection", async () => {
		const h = harness(1);
		await h.ready();
		for (let i = 0; i <= poolLimits.faultRestarts; i++) {
			const job = h.pool.run(`n${i}`);
			h.latest().answer(0, { addresses: ["10.0.0.1"] });
			await job?.answer;
			h.latest().emit("exit");
			if (i < poolLimits.faultRestarts) {
				await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
				h.latest().ready();
			}
		}
		// Refusing at once: the caller drops it unread.
		h.pool.run("dropped")?.unwant();
		await h.settled();
	});

	it("keeps the parent alive by no timer of its own: no restart, look again or wait for ready holds it", async () => {
		const timers: { hasRef(): boolean }[] = [];
		const made = globalThis.setTimeout;
		const spy = vi.spyOn(globalThis, "setTimeout").mockImplementation(((
			fn: () => void,
			ms?: number,
		) => {
			const timer = made(fn, ms) as unknown as { hasRef(): boolean };
			timers.push(timer);
			return timer;
		}) as typeof setTimeout);
		try {
			const h = harness(1);
			await h.ready();
			// A fault: a backoff, then a replacement waiting for its ready.
			h.latest().emit("exit");
			await h.settled();
			await vi.advanceTimersByTimeAsync(poolLimits.backoffMs);
			// Abandoned past the window: a look again.
			h.latest().ready();
			for (let i = 0; i < poolLimits.abandonRestarts; i++) {
				h.pool.run(`n${i}`)?.unwant();
				await h.settled();
				h.latest().ready();
			}
			h.pool.run("left")?.unwant();
			await h.settled();
			expect(timers.length).toBeGreaterThan(2);
			expect(timers.filter((t) => t.hasRef())).toEqual([]);
		} finally {
			spy.mockRestore();
		}
	});

	it("starts one helper however often start is called, sharing the first start", async () => {
		const h = harness(1);
		const first = h.pool.start();
		const second = h.pool.start();
		expect(h.started).toHaveLength(1);
		h.latest().ready();
		await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);
		await h.pool.start();
		expect(h.started).toHaveLength(1);
	});
});
