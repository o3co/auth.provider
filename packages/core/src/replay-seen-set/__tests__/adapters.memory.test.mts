/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMemoryReplaySeenSet,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL,
} from "../adapters/memory.mjs";
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

	it("ignores a nonsensical sweep interval rather than never sweeping", async () => {
		for (const bad of [0, -1, 1.5, Number.NaN]) {
			vi.useFakeTimers();
			const set = createMemoryReplaySeenSet({ sweepInterval: bad });
			await fill(set, DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL - 1, 1_000, "dead");
			vi.advanceTimersByTime(60_000);
			await set.markSeen("scope-A", "trigger", Date.now() + 600_000);
			// The default interval applied: the thousandth write swept.
			expect(set.size).toBe(1);
			vi.useRealTimers();
		}
	});
});
