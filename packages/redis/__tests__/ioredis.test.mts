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
	// Each test warms the module-level `scriptCached` cache from cold within
	// its own body so the suite is order-independent (running any single test
	// via `vitest -t "..."` works in isolation). The first `compareAndDelete`
	// call after module load — or after a prior NOSCRIPT path — runs EVAL;
	// each subsequent call within the same test runs EVALSHA.
	afterEach(() => vi.restoreAllMocks());

	it("first call falls through to EVAL (cold path semantics) and returns true on match", async () => {
		const io = makeFakeIoredis({
			// EVALSHA may or may not be called first depending on whether
			// `scriptCached` is true from a prior test. Both code paths
			// must succeed. In a cold-path call the response is 1 (matched
			// → key deleted).
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		const result = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(result).toBe(true);
		// One of EVAL or EVALSHA was called; total = 1. We don't assert on
		// which because that depends on the prior `scriptCached` state.
		expect(io.eval.mock.calls.length + io.evalsha.mock.calls.length).toBe(1);
	});

	it("after a warmup call the next call uses EVALSHA only (warm path)", async () => {
		// Self-contained: don't depend on whether `scriptCached` is true at
		// test start. Both EVALSHA and EVAL succeed for the warmup so the
		// path taken doesn't matter; the assertion is only on the SECOND
		// call's behavior (EVALSHA increments by 1, EVAL does not).
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(0),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		// Warmup: regardless of cold/warm initial state, scriptCached ends true.
		await federationTokenStoreClient.compareAndDelete("k", "v");
		const evalshaBefore = io.evalsha.mock.calls.length;
		const evalBefore = io.eval.mock.calls.length;

		// Second call: cache is now warm. Must take the EVALSHA path only.
		const result = await federationTokenStoreClient.compareAndDelete("k", "wrong-token");

		expect(result).toBe(false);
		expect(io.evalsha.mock.calls.length).toBe(evalshaBefore + 1);
		expect(io.eval.mock.calls.length).toBe(evalBefore);
	});

	it("NOSCRIPT on EVALSHA falls back to EVAL and re-warms the cache", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		// Warmup so `scriptCached === true` regardless of prior test state.
		await federationTokenStoreClient.compareAndDelete("k", "v");
		const evalAfterWarmup = io.eval.mock.calls.length;

		// Swap EVALSHA to throw NOSCRIPT once, then succeed.
		const noscriptError = new Error("NOSCRIPT No matching script. Please use EVAL.");
		io.evalsha.mockReset().mockRejectedValueOnce(noscriptError).mockResolvedValue(1);

		// Test call 1: EVALSHA throws NOSCRIPT → fallback to EVAL → re-warm.
		const r1 = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(r1).toBe(true);
		expect(io.evalsha.mock.calls.length).toBe(1);
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup + 1);

		// Test call 2: cache flagged warm again → EVALSHA only, no NEW EVAL.
		const r2 = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(r2).toBe(true);
		expect(io.evalsha.mock.calls.length).toBe(2);
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup + 1);
	});

	it("non-NOSCRIPT errors from EVALSHA propagate (no silent fallback)", async () => {
		// Self-contained: warm the cache with both EVALSHA and EVAL succeeding,
		// then swap the EVALSHA mock to reject with a non-NOSCRIPT error and
		// assert the next call propagates that error without falling through.
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		// Warmup ensures `scriptCached === true` regardless of prior test state.
		await federationTokenStoreClient.compareAndDelete("k", "v");
		const evalAfterWarmup = io.eval.mock.calls.length;

		// Swap EVALSHA to reject with ECONNRESET (not NOSCRIPT).
		const networkError = new Error("ECONNRESET: connection lost");
		io.evalsha.mockReset().mockRejectedValue(networkError);

		await expect(federationTokenStoreClient.compareAndDelete("k", "v")).rejects.toThrow(
			/ECONNRESET/,
		);
		// Critical assertion: EVAL is NOT called as a fallback for non-NOSCRIPT errors.
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup);
	});
});
