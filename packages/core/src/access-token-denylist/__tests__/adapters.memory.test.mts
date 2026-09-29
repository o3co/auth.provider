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
 * Bounded growth. `has` drops only the jti it is asked about, and a revoked
 * token is precisely the one that stops being presented, so reclaiming on
 * read alone would keep every revocation forever. The sibling in-memory
 * stores are bounded by what they key on (the rate limiter caps buckets, the
 * subject stores key by subject); this one is keyed by jti, so nothing bounds
 * it but time, and it sweeps on its own.
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
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist();
		await fill(denylist, DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(denylist, DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL, 600_000, "live");
		// Only the live set survives; the expired thousand is gone.
		expect(denylist.size).toBe(DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL);
	});

	it("bounds the resident set at live entries plus one sweep interval", async () => {
		// The sweep is amortized: expired entries are reclaimed within an
		// interval, not the instant they expire. Growth is bounded, not
		// zero-lag.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist({ sweepInterval: 10 });
		await fill(denylist, 100, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(denylist, 25, 600_000, "live");
		expect(denylist.size).toBeLessThanOrEqual(25 + 10);
	});

	it("keeps every live entry when it sweeps", async () => {
		// A sweep that drops a live jti un-revokes a token.
		//
		// The small interval is deliberate: with the default (1000) the trigger
		// adds never reach a sweep, and the assertions would pass with the sweep
		// broken. `size` is asserted rather than `has` because `has` deletes
		// what it finds expired, which hides whether the sweep ran.
		vi.useFakeTimers();
		const denylist = createMemoryAccessTokenDenylist({ sweepInterval: 5 });
		await fill(denylist, 10, 600_000, "live");
		await fill(denylist, 5, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		// Five more adds guarantee a sweep now that the dead set has expired.
		await fill(denylist, 5, 600_000, "trigger");
		// 10 live + 5 trigger; the 5 dead are gone, and nothing read them.
		expect(denylist.size).toBe(15);
		for (let i = 0; i < 10; i += 1) {
			expect(await denylist.has(`live-${i}`)).toBe(true);
		}
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
		// Without it a deployment cannot tell a denylist doing its job from one
		// that keeps growing.
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
