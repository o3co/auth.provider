/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// I-3 — Verify the EVALSHA + EVAL fallback path of
// `makeIoredisClients(...).federationTokenStoreClient.compareAndDelete`. The
// hot path uses `EVALSHA` with a precomputed SHA-1; on `NOSCRIPT` (cold
// server-side script cache after `SCRIPT FLUSH` or cluster failover) the
// adapter falls back to `EVAL`, which Redis implicitly loads into its
// server-side cache so subsequent EVALSHA calls succeed.
//
// Uses a hand-rolled fake of the ioredis `Redis` shape (not testcontainers)
// because the goal is to exercise the adapter's branching logic, not the
// Lua atomicity (which is closed by construction at the Redis server).

import type { Redis } from "ioredis";
import { afterEach, describe, expect, it, vi } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";

interface FakeIoredis {
	evalsha: ReturnType<typeof vi.fn>;
	eval: ReturnType<typeof vi.fn>;
}

function makeFakeIoredis(overrides: Partial<FakeIoredis> = {}): Redis {
	const fake = {
		evalsha: vi.fn(),
		eval: vi.fn(),
		// Stubs for everything else `makeIoredisClients` reads at construction time.
		// The compareAndDelete tests below only exercise evalsha/eval; other
		// methods are unused in the assertions.
		set: vi.fn(),
		get: vi.fn(),
		del: vi.fn(),
		hset: vi.fn(),
		hvals: vi.fn(),
		pexpireat: vi.fn(),
		zadd: vi.fn(),
		zrange: vi.fn(),
		zrem: vi.fn(),
		incr: vi.fn(),
		expire: vi.fn(),
		multi: vi.fn(),
		watch: vi.fn(),
		unwatch: vi.fn(),
		duplicate: vi.fn(),
		scanStream: vi.fn(),
		script: vi.fn(),
		...overrides,
	};
	return fake as unknown as Redis;
}

describe("makeIoredisClients federationTokenStoreClient.compareAndDelete", () => {
	// Module-level `scriptCached` persists across tests in the same module —
	// reset it implicitly by reusing the same fake state across the three
	// tests in serial order: cold → warm → flush+cold.
	afterEach(() => vi.restoreAllMocks());

	it("first call falls through to EVAL (cold cache) and returns true on match", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);
		const result = await federationTokenStoreClient.compareAndDelete("k", "v");

		expect(result).toBe(true);
		// Cold cache: EVAL is the path, not EVALSHA.
		expect(io.eval).toHaveBeenCalledTimes(1);
		// EVALSHA may be called once on the optimistic warm-path attempt only
		// if `scriptCached` was already true from a prior test. The first
		// real-world cold call is EVAL-only.
	});

	it("warm cache: subsequent calls use EVALSHA and skip EVAL", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(0),
			eval: vi.fn(),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);
		// Module-level `scriptCached` is already true from the previous test.
		const result = await federationTokenStoreClient.compareAndDelete("k", "wrong-token");

		expect(result).toBe(false);
		expect(io.evalsha).toHaveBeenCalledTimes(1);
		expect(io.eval).not.toHaveBeenCalled();
	});

	it("NOSCRIPT on EVALSHA falls back to EVAL and re-warms the cache", async () => {
		const noscriptError = new Error("NOSCRIPT No matching script. Please use EVAL.");
		const io = makeFakeIoredis({
			// First EVALSHA throws NOSCRIPT; the second (post-fallback) returns 1.
			evalsha: vi.fn().mockRejectedValueOnce(noscriptError).mockResolvedValueOnce(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		// First call: EVALSHA throws NOSCRIPT → fallback to EVAL → re-warm.
		const r1 = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(r1).toBe(true);
		expect(io.evalsha).toHaveBeenCalledTimes(1);
		expect(io.eval).toHaveBeenCalledTimes(1);

		// Second call: cache flagged warm again → EVALSHA only, no EVAL.
		const r2 = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(r2).toBe(true);
		expect(io.evalsha).toHaveBeenCalledTimes(2);
		expect(io.eval).toHaveBeenCalledTimes(1);
	});

	it("non-NOSCRIPT errors from EVALSHA propagate (no silent fallback)", async () => {
		const networkError = new Error("ECONNRESET: connection lost");
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockRejectedValue(networkError),
			eval: vi.fn(),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		await expect(federationTokenStoreClient.compareAndDelete("k", "v")).rejects.toThrow(
			/ECONNRESET/,
		);
		// Only ECONNRESET — must NOT fall through to EVAL on a non-NOSCRIPT error.
		expect(io.eval).not.toHaveBeenCalled();
	});
});
