/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMemoryAccessTokenDenylist,
	DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL,
} from "../memory.mjs";
import { runAccessTokenDenylistContract } from "./adapters.contract.mjs";

runAccessTokenDenylistContract("memory", {
	create: () => createMemoryAccessTokenDenylist(),
});

afterEach(() => {
	vi.useRealTimers();
});

/*
 * #293 item 6 — the in-memory denylist grew without bound.
 *
 * `add` never pruned, and `has` only ever dropped the one jti it was asked
 * about. So an entry was reclaimed only if someone happened to present that
 * exact token again after it expired — which, for a token that was revoked, is
 * precisely the request that stops coming. Every revocation was a permanent
 * Map entry on a long-running single-process deployment.
 *
 * The sibling in-memory stores are bounded by what they key on: the rate
 * limiter caps buckets and evicts, the subject stores are keyed by subject.
 * This one is keyed by jti, so nothing bounds it but time — which means the
 * sweep has to be its own, not a side effect of a lucky read.
 */
describe("createMemoryAccessTokenDenylist — bounded growth (#293 item 6)", () => {
	/** Fill the denylist with `count` entries expiring `ttlMs` from now. */
	const fill = async (
		denylist: ReturnType<typeof createMemoryAccessTokenDenylist>,
		count: number,
		ttlMs: number,
		prefix = "jti",
	) => {
		for (let i = 0; i < count; i += 1) {
			await denylist.add(`${prefix}-${i}`, Date.now() + ttlMs);
		}
	};

	it("reclaims expired entries that nobody asks about again", async () => {
		// The leak, stated: a revoked token is exactly the one that stops being
		// presented, so lazy-on-read GC never fires for it. Under the old
		// implementation the first thousand would still all be resident here.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist();
		await fill(denylist, DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(denylist, DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL, 600_000, "live");
		// Only the live set survives; the expired thousand is gone.
		expect(denylist.size).toBe(DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL);
	});

	it("bounds the resident set at live entries plus one sweep interval", async () => {
		// The actual guarantee, and worth stating as its own case: the sweep is
		// amortized, so expired entries are reclaimed *within* an interval
		// rather than the instant they expire. Growth is bounded; it is not
		// zero-lag, and a test that pretended otherwise would be pinning
		// something the design does not promise.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist({ sweepInterval: 10 });
		await fill(denylist, 100, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(denylist, 25, 600_000, "live");
		expect(denylist.size).toBeLessThanOrEqual(25 + 10);
	});

	it("keeps every live entry when it sweeps", async () => {
		// A sweep that drops a live jti un-revokes a token, which is worse than
		// the leak it is fixing.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist();
		await fill(denylist, 10, 600_000, "live");
		await fill(denylist, DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await denylist.add("trigger", Date.now() + 600_000);
		for (let i = 0; i < 10; i += 1) {
			expect(await denylist.has(`live-${i}`)).toBe(true);
		}
		expect(await denylist.has("dead-0")).toBe(false);
	});

	it("does not sweep on every add — the work is amortized", async () => {
		// A sweep per add would make revocation O(n) in the size of the
		// denylist, which is the wrong trade on the path that revokes.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist();
		await fill(denylist, 5, 1_000);
		vi.advanceTimersByTime(60_000);
		await denylist.add("one-more", Date.now() + 600_000);
		// Well under the interval, so the expired five are still resident.
		expect(denylist.size).toBe(6);
	});

	it("still answers correctly for an expired entry it has not swept yet", async () => {
		// Bounded growth must not change what `has` reports: an unswept
		// expired entry is still not revoked.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist();
		await denylist.add("jti-1", Date.now() + 1_000);
		vi.advanceTimersByTime(60_000);
		expect(await denylist.has("jti-1")).toBe(false);
	});

	it("exposes its size so an operator can see the bound holding", async () => {
		// The whole failure mode was invisible; a deployment had no way to tell
		// a denylist doing its job from one that had been growing for a month.
		const denylist = createMemoryAccessTokenDenylist();
		expect(denylist.size).toBe(0);
		await denylist.add("jti-1", Date.now() + 600_000);
		expect(denylist.size).toBe(1);
	});

	it("takes a sweep interval so a deployment can trade memory against work", async () => {
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist({ sweepInterval: 2 });
		await fill(denylist, 2, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(denylist, 2, 600_000, "live");
		expect(denylist.size).toBe(2);
	});

	it("ignores a nonsensical sweep interval rather than never sweeping", async () => {
		// A zero or negative interval would make `addsSinceSweep >= interval`
		// true on every add (or the config a silent no-op, depending on the
		// comparison) — neither is what an operator meant, so it falls back.
		for (const bad of [0, -1, 1.5, Number.NaN]) {
			const denylist = createMemoryAccessTokenDenylist({ sweepInterval: bad });
			await denylist.add("jti-1", Date.now() + 600_000);
			expect(denylist.size).toBe(1);
		}
	});
});
