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

import { EventEmitter } from "node:events";
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

// ---------------------------------------------------------------------------
// Duplicated connections must not be able to crash the process
//
// `refreshTokenFamilyClient.duplicate()` opens a fresh ioredis connection per
// refresh rotation, and ioredis `duplicate()` copies options but NOT event
// listeners — a duplicate starts with zero `error` listeners. An EventEmitter
// `error` with no listener throws, so a socket blip on any of those short-lived
// connections took the provider down. Same crash class as the node-redis
// session client, on a much hotter path.
// ---------------------------------------------------------------------------

describe("makeIoredisClients refreshTokenFamilyClient.duplicate", () => {
	class FakeDuplicate extends EventEmitter {
		set = vi.fn();
		get = vi.fn();
		pttl = vi.fn();
		watch = vi.fn();
		unwatch = vi.fn();
		multi = vi.fn();
		quit = vi.fn().mockResolvedValue("OK");
		disconnect = vi.fn();
		duplicate = vi.fn();
	}

	function makeParentWithDuplicate(dup: FakeDuplicate): Redis {
		return makeFakeIoredis({ duplicate: vi.fn(() => dup) as never });
	}

	it("attaches an error listener to the duplicated connection", async () => {
		const dup = new FakeDuplicate();
		const clients = makeIoredisClients(makeParentWithDuplicate(dup));

		const disposable = clients.refreshTokenFamilyClient.duplicate();

		expect(dup.listenerCount("error")).toBe(1);
		expect(() => dup.emit("error", new Error("ECONNRESET"))).not.toThrow();
		await disposable[Symbol.asyncDispose]();
	});

	it("reports the duplicated connection's errors through the supplied logger", async () => {
		const error = vi.fn();
		const dup = new FakeDuplicate();
		const clients = makeIoredisClients(makeParentWithDuplicate(dup), {
			logger: { warn: vi.fn(), error },
		});

		const disposable = clients.refreshTokenFamilyClient.duplicate();
		dup.emit("error", new Error("ECONNRESET"));

		expect(error).toHaveBeenCalledTimes(1);
		expect(error.mock.calls[0]?.[1]).toBe("redis_duplicate_connection_error");
		await disposable[Symbol.asyncDispose]();
	});

	it("falls back to disconnect() when quit() rejects, so disposal never throws", async () => {
		// This runs on an `await using` binding around a refresh rotation. A
		// rejecting disposal reports failure for a rotation that already
		// committed — the client then retries with the old refresh token, replay
		// detection fires, and the whole family is revoked. And when the body
		// already threw, a rejecting disposal buries the original error inside a
		// SuppressedError.
		const dup = new FakeDuplicate();
		dup.quit = vi.fn().mockRejectedValue(new Error("Connection is closed."));
		const clients = makeIoredisClients(makeParentWithDuplicate(dup));

		const disposable = clients.refreshTokenFamilyClient.duplicate();

		await expect(disposable[Symbol.asyncDispose]()).resolves.toBeUndefined();
		expect(dup.disconnect).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// Copilot review on PR #352 — MULTI/EXEC per-command errors must not be
// swallowed.
//
// ioredis resolves `exec()` with a `[error, result]` tuple per queued command
// and does NOT reject when one of them failed. Every pipeline in this file used
// to discard that reply, so a `PEXPIRE … NX/GT` rejected by an older or
// misconfigured Redis left the key with no TTL while the caller was told the
// write succeeded — the exact failure mode the atomic-TTL contract exists to
// rule out, and the one #269 already paid for once with the rate limiter.
//
// `null` is different and must stay: it is the WATCH-abort signal
// `refresh-token-family`'s CAS loop reads as "conflict, retry".
// ---------------------------------------------------------------------------

/** A chainable ioredis pipeline stub whose `exec()` resolves to `reply`. */
function makeFakePipeline(reply: unknown) {
	const pipeline: Record<string, unknown> = {
		exec: vi.fn(async () => reply),
	};
	for (const cmd of ["sadd", "pexpire", "hset", "pexpireat", "zadd", "set"]) {
		pipeline[cmd] = vi.fn(() => pipeline);
	}
	return pipeline;
}

const WRONGTYPE = new Error("WRONGTYPE Operation against a key holding the wrong kind of value");

describe("makeIoredisClients — MULTI/EXEC replies are inspected", () => {
	it("sAddWithTtl rejects when a queued command failed", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[WRONGTYPE, null]])) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).rejects.toThrow(/WRONGTYPE/);
	});

	it("sAddWithTtl resolves when every queued command succeeded", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() =>
				makeFakePipeline([
					[null, 1],
					[null, 1],
					[null, 0],
				]),
			) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).resolves.toBeUndefined();
	});

	it("sessionRPRegistryClient.multi().exec() rejects on a failed queued command", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() =>
				makeFakePipeline([
					[null, 1],
					[WRONGTYPE, null],
				]),
			) as never,
		});
		const p = makeIoredisClients(io).sessionRPRegistryClient.multi();
		p.hSet("k", "f", "v").pExpireGT("k", Date.now() + 1000);
		await expect(p.exec()).rejects.toThrow(/WRONGTYPE/);
	});

	it("sessionFamilyIndexClient.multi().exec() rejects on a failed queued command", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[WRONGTYPE, null]])) as never,
		});
		const p = makeIoredisClients(io).sessionFamilyIndexClient.multi();
		p.zAdd("k", { score: 1, value: "m" }, { NX: true });
		await expect(p.exec()).rejects.toThrow(/WRONGTYPE/);
	});

	it("refreshTokenFamilyClient.multi().exec() rejects on a failed queued command", async () => {
		// The CAS loop reports `committed` on a non-null reply. A silently
		// failed SET would be reported as a successful rotation.
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[new Error("OOM command not allowed"), null]])) as never,
		});
		const p = makeIoredisClients(io).refreshTokenFamilyClient.multi();
		p.set("k", "v", "PX", 1000);
		await expect(p.exec()).rejects.toThrow(/OOM/);
	});

	it("refreshTokenFamilyClient.multi().exec() still returns null for a WATCH abort", async () => {
		// Load-bearing: `updateFamily` reads null as "CAS conflict, retry".
		// Turning it into a throw would break refresh-token rotation under
		// contention.
		const io = makeFakeIoredis({ multi: vi.fn(() => makeFakePipeline(null)) as never });
		const p = makeIoredisClients(io).refreshTokenFamilyClient.multi();
		p.set("k", "v", "PX", 1000);
		await expect(p.exec()).resolves.toBeNull();
	});
});

describe("makeIoredisClients — MULTI/EXEC reply shapes the check must survive", () => {
	it("treats a bare (non-tuple) result as success, for a driver that does not wrap", async () => {
		// node-redis and friends resolve `exec()` with plain results and reject
		// on error, so there is no error slot to find. Reading `[0]` off such a
		// value would misread the first result as an error — `0`, `""` and
		// `null` are all legal results, and a truthy one (say the `1` from a
		// successful SADD) would be reported as a failure. Fail on the shape we
		// actually get, not on every shape we might.
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([1, "OK", 0])) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).resolves.toBeUndefined();
	});

	it("reports a non-Error rejection value without stringifying it as [object Object]", async () => {
		// Redis replies arrive as `ReplyError`, but a mocked or exotic driver
		// can put anything in the slot. The operator still needs to read it.
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([["EXECABORT Transaction discarded", null]])) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).rejects.toThrow(/EXECABORT Transaction discarded/);
	});
});
