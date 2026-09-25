/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMemoryReplaySeenSet,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL,
	ReplaySeenSetFullError,
} from "#/replay-seen-set/adapters/memory.mjs";
import { ChallengeStorageError } from "#/single-use/errors.mjs";
import { runReplaySeenSetContract } from "./adapters.contract.mjs";

runReplaySeenSetContract("memory", {
	create: () => createMemoryReplaySeenSet(),
});

afterEach(() => {
	vi.useRealTimers();
});

/*
 * The in-memory seen-set grew without bound.
 *
 * `markSeen` never pruned, and a record was dropped only when that exact
 * (scope, key) was asked about again after it expired. Every consumer records
 * a value that is never presented again once it has been honoured — a client
 * assertion's `jti`, an ID-JAG's `jti`, a DPoP proof's `jti` — so nothing was
 * ever reclaimed: one permanent Map entry per accepted assertion or proof on a
 * long-running single-process deployment. DPoP records one per request at
 * every protected resource. The access-token denylist had the same leak and
 * the same fix (#293 item 6).
 */
describe("createMemoryReplaySeenSet — bounded growth", () => {
	/** Record `count` keys under `scope` that expire `ttlMs` from now. */
	const fill = async (
		set: ReturnType<typeof createMemoryReplaySeenSet>,
		count: number,
		ttlMs: number,
		prefix = "jti",
		scope = "scope-A",
	) => {
		for (let i = 0; i < count; i += 1) {
			expect(await set.markSeen(scope, `${prefix}-${i}`, Date.now() + ttlMs)).toBe(true);
		}
	};

	it("reclaims expired records that nobody asks about again", async () => {
		// Pinned first so the fills below cannot be vacuous.
		expect(DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL).toBe(1_000);
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet();
		await fill(set, DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(set, DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL, 600_000, "live");
		// Only the live records survive; the expired thousand is gone.
		expect(set.size).toBe(DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL);
	});

	it("bounds the resident set at live records plus one sweep interval", async () => {
		// The sweep is amortized: an expired record is reclaimed within an
		// interval, not the instant it expires.
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 10 });
		await fill(set, 100, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(set, 25, 600_000, "live");
		expect(set.size).toBeLessThanOrEqual(25 + 10);
	});

	it("keeps every live record when it sweeps, whatever scope it is in", async () => {
		// A sweep that drops a live record lets its value be accepted again —
		// a replay, which is worse than the leak it fixes. The consumers share
		// one set under different scopes and different lifetimes, so the live
		// records sit in several scopes with expiries both before and after
		// the dead ones.
		//
		// Asserting on `size` rather than on `markSeen` alone: `markSeen`
		// drops the one record it finds expired, so reading through it hides
		// whether the sweep ran.
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 5 });
		await fill(set, 10, 600_000, "live", "client-assertion:c1");
		await fill(set, 5, 1_000, "dead", "dpop-proof:k1");
		vi.advanceTimersByTime(60_000);
		// Five more writes guarantee a sweep now that the dead ones have expired.
		await fill(set, 5, 600_000, "trigger", "dpop-proof:k2");
		// 10 live + 5 trigger; the 5 dead are gone.
		expect(set.size).toBe(15);
		for (let i = 0; i < 10; i += 1) {
			expect(await set.contains("client-assertion:c1", `live-${i}`)).toBe(true);
			expect(await set.markSeen("client-assertion:c1", `live-${i}`, Date.now() + 1_000)).toBe(
				false,
			);
		}
	});

	it("does not sweep on every write — the work is amortized", async () => {
		// A sweep per write would make every accepted proof O(n) in the size
		// of the set.
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet();
		await fill(set, 5, 1_000);
		vi.advanceTimersByTime(60_000);
		await set.markSeen("scope-A", "one-more", Date.now() + 600_000);
		// Well under the interval, so the expired five are still resident.
		expect(set.size).toBe(6);
	});

	it("does not count a replay as a write", async () => {
		// Only a write grows the set, so only a write pays towards the next
		// sweep: a burst of replays is refused without adding work.
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 3 });
		await fill(set, 2, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await set.markSeen("scope-A", "live", Date.now() + 600_000);
		// That third write swept the two expired records.
		expect(set.size).toBe(1);
		for (let i = 0; i < 5; i += 1) {
			expect(await set.markSeen("scope-A", "live", Date.now() + 600_000)).toBe(false);
		}
		expect(set.size).toBe(1);
	});

	it("still answers correctly for an expired record it has not swept yet", async () => {
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet();
		await set.markSeen("scope-A", "jti-1", Date.now() + 1_000);
		vi.advanceTimersByTime(60_000);
		expect(await set.contains("scope-A", "jti-1")).toBe(false);
		expect(await set.markSeen("scope-A", "jti-1", Date.now() + 1_000)).toBe(true);
	});

	it("exposes its size so an operator can see the bound holding", async () => {
		const set = createMemoryReplaySeenSet();
		expect(set.size).toBe(0);
		await set.markSeen("scope-A", "jti-1", Date.now() + 600_000);
		expect(set.size).toBe(1);
	});

	it("refuses a sweep interval that is not a positive whole number, rather than using another", () => {
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => createMemoryReplaySeenSet({ sweepInterval: bad }), String(bad)).toThrow(
				new RangeError(
					`createMemoryReplaySeenSet: sweepInterval must be a positive whole number (got ${String(bad)})`,
				),
			);
		}
	});
});

/*
 * A sweep scans the whole map, and a write count alone does not bound how
 * often that happens: DPoP writes a record on every request at every
 * protected resource, so at 1000 requests a second a 1000-write interval
 * is one full scan a second — of about 300,000 records at the default
 * 300-second replay TTL. A time floor caps the scans at one per interval
 * whatever the write rate, for a resident set larger by at most the
 * records that expire within it.
 */
describe("createMemoryReplaySeenSet — sweeps are also bounded in time", () => {
	const fill = async (
		set: ReturnType<typeof createMemoryReplaySeenSet>,
		count: number,
		ttlMs: number,
		prefix: string,
	) => {
		for (let i = 0; i < count; i += 1) {
			await set.markSeen("scope-A", `${prefix}-${i}`, Date.now() + ttlMs);
		}
	};

	it("sweeps at most once per minSweepIntervalMs, however fast the writes come", async () => {
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 5, minSweepIntervalMs: 1_000 });
		// The fifth write sweeps (nothing has expired yet).
		await fill(set, 5, 10, "early");
		vi.advanceTimersByTime(20);
		// Five more writes reach the interval again, but inside the floor: the
		// five expired records are still resident.
		await fill(set, 5, 600_000, "burst");
		expect(set.size).toBe(10);
		// Once the floor has passed, the next write sweeps them.
		vi.advanceTimersByTime(1_000);
		await set.markSeen("scope-A", "late", Date.now() + 600_000);
		expect(set.size).toBe(6);
	});

	it("keeps counting writes through the floor, so the first write after it sweeps", async () => {
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 3, minSweepIntervalMs: 1_000 });
		await fill(set, 3, 10, "a"); // sweeps at the third write
		vi.advanceTimersByTime(20);
		await fill(set, 7, 600_000, "b"); // interval reached twice over, inside the floor
		expect(set.size).toBe(10);
		vi.advanceTimersByTime(1_000);
		await set.markSeen("scope-A", "c", Date.now() + 600_000);
		expect(set.size).toBe(8);
	});

	it("has a default floor of ten seconds", async () => {
		expect(DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS).toBe(10_000);
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 2 });
		await fill(set, 2, 10, "a"); // first sweep
		vi.advanceTimersByTime(9_000);
		await fill(set, 2, 600_000, "b");
		expect(set.size).toBe(4);
		vi.advanceTimersByTime(1_000);
		await set.markSeen("scope-A", "c", Date.now() + 600_000);
		expect(set.size).toBe(3);
	});

	it("measures the floor on a monotonic clock, so a backward wall-clock jump does not stall sweeps", async () => {
		// Record expiry is wall-clock (the callers' `expiresAtMs`), but the floor
		// is only "how long since the last sweep". Measured on `Date.now()`, a
		// wall clock stepped back an hour (NTP, a restored VM) reads as a
		// negative interval, and sweeps stop until wall time catches up with
		// the last one. vitest's fake timers drive `performance.now()` too, and
		// leave it untouched by `setSystemTime` — as the real monotonic clock is
		// by a wall-clock step.
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ sweepInterval: 2, minSweepIntervalMs: 1_000 });
		await fill(set, 2, 600_000, "before"); // first sweep
		vi.setSystemTime(Date.now() - 3_600_000);
		await fill(set, 2, 10, "after-jump"); // inside the floor: no sweep
		expect(set.size).toBe(4);
		vi.advanceTimersByTime(1_000);
		await set.markSeen("scope-A", "trigger", Date.now() + 600_000);
		// A second of monotonic time has passed: the two records that expired on
		// the (jumped) wall clock are gone; the live ones stay.
		expect(set.size).toBe(3);
	});

	it("takes a floor of zero as no floor, and refuses one that is not a whole number of milliseconds", async () => {
		vi.useFakeTimers();
		const unfloored = createMemoryReplaySeenSet({ sweepInterval: 2, minSweepIntervalMs: 0 });
		await fill(unfloored, 2, 10, "a");
		vi.advanceTimersByTime(20);
		await fill(unfloored, 2, 600_000, "b");
		expect(unfloored.size).toBe(2);

		for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(
				() => createMemoryReplaySeenSet({ sweepInterval: 2, minSweepIntervalMs: bad }),
				String(bad),
			).toThrow(
				new RangeError(
					`createMemoryReplaySeenSet: minSweepIntervalMs must be a whole number of milliseconds, 0 or more (got ${String(bad)})`,
				),
			);
		}
	});
});

/*
 * Nothing bounded the set but time. DPoP records a proof before the token
 * endpoint's rate limit runs and before a protected resource has verified
 * the access token, so anyone can have it write one 300-second record per
 * request: the set grew with the request rate, until the process ran out of
 * memory. A cap on the records it holds bounds it; at the cap it refuses a
 * new record as a store fault — the set cannot record it, so the value is
 * not accepted — the way a Redis seen-set refuses a write at `maxmemory`
 * under `noeviction`. It never evicts a live record, which would let the
 * value it held be replayed.
 */
describe("createMemoryReplaySeenSet — a cap on the records it holds", () => {
	const later = (): number => Date.now() + 600_000;

	it("holds at most a million records by default, and says what its cap is", () => {
		// A million: at DPoP's default 300-second window, filling it takes some
		// 3 300 fresh proofs a second, each verified first — about what one
		// process can verify at all — rather than a rate one client sends idly.
		expect(DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES).toBe(1_000_000);
		expect(createMemoryReplaySeenSet().maxEntries).toBe(DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES);
		expect(createMemoryReplaySeenSet({ maxEntries: 5 }).maxEntries).toBe(5);
	});

	it("refuses a new record at its cap as a store fault, recording nothing and evicting nothing", async () => {
		const set = createMemoryReplaySeenSet({ maxEntries: 2 });
		expect(await set.markSeen("dpop-proof:k1", "jti-1", later())).toBe(true);
		expect(await set.markSeen("client-assertion:c1", "jti-2", later())).toBe(true);

		const refusal = await set.markSeen("dpop-proof:k1", "jti-3", later()).then(
			() => undefined,
			(err: unknown) => err,
		);
		expect(refusal).toBeInstanceOf(ReplaySeenSetFullError);
		// Not the port's contract errors, which a consumer reads as its own
		// fault (`expired-at-issue`, a RangeError): a store that cannot record.
		expect(refusal).not.toBeInstanceOf(ChallengeStorageError);
		expect(refusal).not.toBeInstanceOf(RangeError);
		expect(refusal).toMatchObject({ name: "ReplaySeenSetFullError", reason: "full" });
		expect((refusal as Error).message).toBe(
			"memory ReplaySeenSet is at its cap of 2 live records; refusing a new one rather than evicting one",
		);

		expect(set.size).toBe(2);
		expect(await set.contains("dpop-proof:k1", "jti-3")).toBe(false);
		expect(await set.contains("dpop-proof:k1", "jti-1")).toBe(true);
		expect(await set.contains("client-assertion:c1", "jti-2")).toBe(true);
	});

	it("still refuses a replay at its cap: a replay writes nothing", async () => {
		const set = createMemoryReplaySeenSet({ maxEntries: 1 });
		expect(await set.markSeen("scope-A", "jti-1", later())).toBe(true);
		expect(await set.markSeen("scope-A", "jti-1", later())).toBe(false);
	});

	it("reclaims expired records before it refuses", async () => {
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ maxEntries: 2, minSweepIntervalMs: 0 });
		expect(await set.markSeen("scope-A", "short", Date.now() + 1_000)).toBe(true);
		expect(await set.markSeen("scope-A", "long", later())).toBe(true);
		vi.advanceTimersByTime(2_000);
		expect(await set.markSeen("scope-A", "next", later())).toBe(true);
		expect(set.size).toBe(2);
		expect(await set.contains("scope-A", "long")).toBe(true);
	});

	it("scans for expired records at its cap no more often than its sweep floor", async () => {
		// Under a flood the set sits at its cap, and a scan per refused write
		// would make every request O(size).
		vi.useFakeTimers();
		const set = createMemoryReplaySeenSet({ maxEntries: 2, minSweepIntervalMs: 1_000 });
		await set.markSeen("scope-A", "a", Date.now() + 10);
		await set.markSeen("scope-A", "b", Date.now() + 10);
		// At the cap, nothing expired yet: this write's scan finds nothing.
		await expect(set.markSeen("scope-A", "c", later())).rejects.toBeInstanceOf(
			ReplaySeenSetFullError,
		);
		vi.advanceTimersByTime(20);
		// Both records have expired, but the floor has not passed: no scan.
		await expect(set.markSeen("scope-A", "d", later())).rejects.toBeInstanceOf(
			ReplaySeenSetFullError,
		);
		vi.advanceTimersByTime(1_000);
		expect(await set.markSeen("scope-A", "e", later())).toBe(true);
		expect(set.size).toBe(1);
	});

	it("refuses a cap that is not a positive whole number, rather than holding no cap", () => {
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => createMemoryReplaySeenSet({ maxEntries: bad }), String(bad)).toThrow(
				new RangeError(
					`createMemoryReplaySeenSet: maxEntries must be a positive whole number (got ${String(bad)})`,
				),
			);
		}
	});
});
