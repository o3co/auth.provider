/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// The EVALSHA + EVAL fallback of
// `makeIoredisClients(...).federationTokenStoreClient.compareAndDelete`. The
// hot path uses `EVALSHA` with a precomputed SHA-1; on `NOSCRIPT` (a cold
// script cache after `SCRIPT FLUSH` or cluster failover) it falls back to
// `EVAL`, which loads the script so later EVALSHA calls succeed.
//
// A hand-rolled fake of the ioredis `Redis` shape, not a container: the
// subject is the adapter's branching, not the Lua atomicity the server gives.

import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { DeviceCodeStoreError } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FederationGrantStoreClient } from "#/clients.mjs";
import { createRedisDeviceCodeStore } from "#/device-code-store.mjs";
import { makeIoredisClients, makeIoredisFederationGrantStoreClient } from "#/ioredis.mjs";

/** The fake's members a test replaces or reads back as mocks. */
interface FakeIoredis {
	evalsha: ReturnType<typeof vi.fn>;
	eval: ReturnType<typeof vi.fn>;
	multi: ReturnType<typeof vi.fn>;
	duplicate: ReturnType<typeof vi.fn>;
}

function makeFakeIoredis(overrides: Partial<FakeIoredis> = {}): Redis & FakeIoredis {
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
	return fake as unknown as Redis & FakeIoredis;
}

describe("makeIoredisClients federationTokenStoreClient.compareAndDelete", () => {
	// Each test warms the module-level residency flag from cold within
	// its own body so the suite is order-independent (running any single test
	// via `vitest -t "..."` works in isolation). The first `compareAndDelete`
	// call after module load — or after a prior NOSCRIPT path — runs EVAL;
	// each subsequent call within the same test runs EVALSHA.
	afterEach(() => vi.restoreAllMocks());

	it("first call falls through to EVAL (cold path semantics) and returns true on match", async () => {
		const io = makeFakeIoredis({
			// EVALSHA may or may not be called first depending on whether
			// the residency flag is true from a prior test. Both code paths
			// must succeed. In a cold-path call the response is 1 (matched
			// → key deleted).
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		const result = await federationTokenStoreClient.compareAndDelete("k", "v");
		expect(result).toBe(true);
		// One of EVAL or EVALSHA was called; total = 1. We don't assert on
		// which because that depends on the prior residency flag.
		expect(io.eval.mock.calls.length + io.evalsha.mock.calls.length).toBe(1);
	});

	it("after a warmup call the next call uses EVALSHA only (warm path)", async () => {
		// Self-contained: don't depend on whether the residency flag is true at
		// test start. Both EVALSHA and EVAL succeed for the warmup so the
		// path taken doesn't matter; the assertion is only on the SECOND
		// call's behavior (EVALSHA increments by 1, EVAL does not).
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(0),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { federationTokenStoreClient } = makeIoredisClients(io);

		// Warmup: regardless of cold/warm initial state, the residency flag ends true.
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

		// Warmup so the residency flag is true regardless of prior test state.
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

		// Warmup ensures the residency flag is true regardless of prior test state.
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
// connections would take the provider down.
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
// MULTI/EXEC per-command errors must not be swallowed. ioredis resolves
// `exec()` with a `[error, result]` tuple per queued command and does NOT
// reject when one failed. A pipeline that discards that reply leaves the key
// with no TTL when an older or misconfigured Redis rejects a `PEXPIRE … NX/GT`,
// while the caller is told the write succeeded: what the atomic-TTL contract
// exists to rule out. `null` is different and must stay: it is the WATCH-abort
// signal `refresh-token-family`'s CAS loop reads as "conflict, retry".
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

/**
 * What a failed queued command is thrown as: the operation in fixed words,
 * the reply's error as `cause` and nowhere in the message — the reply is
 * Redis's text about the command it refused, and can quote its arguments.
 */
const queuedFailure = (operation: string, cause: unknown) => ({
	message: `${operation}: a queued command failed inside MULTI/EXEC`,
	cause,
});

describe("makeIoredisClients — MULTI/EXEC replies are inspected", () => {
	it("sAddWithTtl rejects when a queued command failed", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[WRONGTYPE, null]])) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).rejects.toMatchObject(queuedFailure("federationTokenStoreClient.sAddWithTtl", WRONGTYPE));
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
		await expect(p.exec()).rejects.toMatchObject(
			queuedFailure("sessionRPRegistryClient.exec", WRONGTYPE),
		);
	});

	it("sessionFamilyIndexClient.multi().exec() rejects on a failed queued command", async () => {
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[WRONGTYPE, null]])) as never,
		});
		const p = makeIoredisClients(io).sessionFamilyIndexClient.multi();
		p.zAdd("k", { score: 1, value: "m" }, { NX: true });
		await expect(p.exec()).rejects.toMatchObject(
			// The family and federation indexes share one sorted-set client.
			queuedFailure("sessionSidSortedSetClient.exec", WRONGTYPE),
		);
	});

	it("refreshTokenFamilyClient.multi().exec() rejects on a failed queued command", async () => {
		// The CAS loop reports `committed` on a non-null reply. A silently
		// failed SET would be reported as a successful rotation.
		const oom = new Error("OOM command not allowed");
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([[oom, null]])) as never,
		});
		const p = makeIoredisClients(io).refreshTokenFamilyClient.multi();
		p.set("k", "v", "PX", 1000);
		await expect(p.exec()).rejects.toMatchObject(
			queuedFailure("refreshTokenFamilyClient.exec", oom),
		);
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

	it("keeps a non-Error value in the slot as the cause, as it is", async () => {
		// Redis replies arrive as `ReplyError`, but a mocked or exotic driver
		// can put anything in the slot. It is still a failure, and it is kept
		// whole on `cause` rather than turned into text.
		const io = makeFakeIoredis({
			multi: vi.fn(() => makeFakePipeline([["EXECABORT Transaction discarded", null]])) as never,
		});
		await expect(
			makeIoredisClients(io).federationTokenStoreClient.sAddWithTtl("k", "m", 1000),
		).rejects.toMatchObject(
			queuedFailure("federationTokenStoreClient.sAddWithTtl", "EXECABORT Transaction discarded"),
		);
	});
});

describe("makeIoredisClients — one connection in, one connection used", () => {
	// The composition root's offline-queue and timeout settings rest on this.
	// `enableOfflineQueue`, `commandTimeout`, `connectTimeout` and
	// `maxRetriesPerRequest` are per-CONNECTION ioredis options, so "shed load
	// immediately on the rate-limiter client, tolerate a reconnect blip
	// everywhere else" is only expressible if the purposes sit on different
	// sockets. They do not: every client below issues its commands against the
	// single `Redis` passed in, and the wrapper opens nothing of its own at
	// construction. If this test has to change, the composition root's timeout
	// comment has to change with it.
	it("routes every purpose's commands to the passed-in Redis and opens no second socket", async () => {
		const io = makeFakeIoredis({
			pttl: vi.fn().mockResolvedValue(1),
			exists: vi.fn().mockResolvedValue(0),
			get: vi.fn().mockResolvedValue(null),
			hset: vi.fn().mockResolvedValue(1),
			zrange: vi.fn().mockResolvedValue([]),
			zrem: vi.fn().mockResolvedValue(0),
			getdel: vi.fn().mockResolvedValue(null),
			// The increment script answers `{count, pttl}`.
			eval: vi.fn().mockResolvedValue([1, 60_000]),
		} as never);
		const c = makeIoredisClients(io);

		await c.challengeStoreClient.pttl("ch");
		await c.accessTokenDenylistClient.exists("jti");
		await c.replaySeenSetClient.exists("jti");
		await c.refreshTokenFamilyClient.get("fam");
		await c.userSessionStoreClient.get("sid");
		await c.sessionRPRegistryClient.hSet("rp", "f", "v");
		await c.sessionFamilyIndexClient.zRange("fam-idx", 0, -1);
		await c.sessionFederationIndexClient.zRem("fed-idx", "m");
		await c.federationTokenStoreClient.get("ft");
		await c.rateLimiterClient.incrementWithTtl("token:ip:1.2.3.4", 60);
		await c.codeRepositoryClient.getDel("code");
		await c.deviceCodeStoreClient.remove(
			{ codeKeyPrefix: "devauth:{devauth}:code:", userKeyPrefix: "devauth:{devauth}:user:" },
			"dc",
		);
		await c.consentStoreClient.revoke("consent:rec:1:u|1:c");
		await c.pendingConsentStoreClient.get(
			{ recordKeyPrefix: "consent:{pending}:ch:", sessionKeyPrefix: "consent:{pending}:sess:" },
			"ch",
			1_000,
		);

		const fake = io as unknown as Record<string, ReturnType<typeof vi.fn>>;
		for (const method of [
			"pttl",
			"exists",
			"get",
			"hset",
			"zrange",
			"zrem",
			"getdel",
			"eval",
			"del",
		]) {
			expect(
				fake[method],
				`${method} went somewhere other than the passed-in connection`,
			).toHaveBeenCalled();
		}
		// The one place this wrapper does open its own connection is
		// `refreshTokenFamilyClient.duplicate()`, per rotation — not per purpose,
		// and not at construction.
		expect(fake.duplicate).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// The device-code store's scripts take the same EVALSHA-first path as
// `compareAndDelete`, through one shared runner. The runner is what these pin:
// a cold cache is recovered by EVAL, and anything that is not NOSCRIPT is the
// caller's error.
// ---------------------------------------------------------------------------

describe("makeIoredisClients deviceCodeStoreClient — EVALSHA-first with NOSCRIPT fallback", () => {
	const keys = {
		codeKeyPrefix: "devauth:{devauth}:code:",
		userKeyPrefix: "devauth:{devauth}:user:",
	};

	it("NOSCRIPT on EVALSHA falls back to EVAL and re-warms the cache", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(["pending"]),
			eval: vi.fn().mockResolvedValue(["pending"]),
		});
		const { deviceCodeStoreClient } = makeIoredisClients(io);

		// Warmup: whatever the script's residency flag was, it ends true.
		await deviceCodeStoreClient.poll(keys, "dc", 1_000, 5);
		const evalAfterWarmup = io.eval.mock.calls.length;

		io.evalsha
			.mockReset()
			.mockRejectedValueOnce(new Error("NOSCRIPT No matching script. Please use EVAL."))
			.mockResolvedValue(["pending"]);

		expect(await deviceCodeStoreClient.poll(keys, "dc", 2_000, 5)).toEqual({ kind: "pending" });
		expect(io.evalsha.mock.calls.length).toBe(1);
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup + 1);

		expect(await deviceCodeStoreClient.poll(keys, "dc", 3_000, 5)).toEqual({ kind: "pending" });
		expect(io.evalsha.mock.calls.length).toBe(2);
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup + 1);
	});

	it("non-NOSCRIPT errors from EVALSHA propagate (no silent fallback)", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(["pending"]),
			eval: vi.fn().mockResolvedValue(["pending"]),
		});
		const { deviceCodeStoreClient } = makeIoredisClients(io);
		await deviceCodeStoreClient.poll(keys, "dc", 1_000, 5);
		const evalAfterWarmup = io.eval.mock.calls.length;

		io.evalsha.mockReset().mockRejectedValue(new Error("ECONNRESET: connection lost"));

		await expect(deviceCodeStoreClient.poll(keys, "dc", 2_000, 5)).rejects.toThrow(/ECONNRESET/);
		expect(io.eval.mock.calls.length).toBe(evalAfterWarmup);
	});

	it("declares the record key and the index key to the script on create", async () => {
		// Cluster routes a script by the keys it declares. `create` is the one
		// operation that knows both keys up front, so it declares both; the
		// others reach the second key through the shared hash tag.
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { deviceCodeStoreClient } = makeIoredisClients(io);
		await deviceCodeStoreClient.create(keys, {
			deviceCode: "dc",
			userCode: "BCDFGHJK",
			expiresAtMs: 5_000,
			fields: {
				userCode: "BCDFGHJK",
				clientId: "tv",
				expiresAtMs: "5000",
				intervalSeconds: "5",
				status: "pending",
			},
		});
		const call = [...io.eval.mock.calls, ...io.evalsha.mock.calls].at(-1) as unknown[];
		expect(call.slice(1, 4)).toEqual([
			2,
			"devauth:{devauth}:code:dc",
			"devauth:{devauth}:user:BCDFGHJK",
		]);
	});
});

describe("makeIoredisClients deviceCodeStoreClient.create — the script's reply, read strictly", () => {
	const keys = {
		codeKeyPrefix: "devauth:{devauth}:code:",
		userKeyPrefix: "devauth:{devauth}:user:",
	};
	const input = {
		deviceCode: "dc",
		userCode: "BCDFGHJK",
		expiresAtMs: 5_000,
		fields: {
			userCode: "BCDFGHJK",
			clientId: "tv",
			expiresAtMs: "5000",
			intervalSeconds: "5",
			status: "pending" as const,
		},
	};
	const replying = (reply: unknown) =>
		makeIoredisClients(
			makeFakeIoredis({
				evalsha: vi.fn().mockResolvedValue(reply),
				eval: vi.fn().mockResolvedValue(reply),
			}),
		).deviceCodeStoreClient;

	it("answers true for 1 (written) and false for 0 (a key already there)", async () => {
		expect(await replying(1).create(keys, input)).toBe(true);
		expect(await replying(0).create(keys, input)).toBe(false);
	});

	it("throws on any other reply, rather than reading it as a collision", async () => {
		// Read as "not 1, so a key already exists", a proxy's "OK", a nil or a
		// changed script's array would each be a collision, re-drawn five times
		// and answered 500, when the store had said something this client does
		// not understand.
		for (const reply of [null, "OK", 2, "1", [1], { ok: 1 }]) {
			await expect(replying(reply).create(keys, input), JSON.stringify(reply)).rejects.toThrow(
				/unexpected reply/,
			);
		}
	});

	it("so the store reports it as a failure, not as the collision signal the endpoint re-draws for", async () => {
		const store = createRedisDeviceCodeStore({ client: replying("OK"), keyPrefix: "devauth:" });
		const refused = await store
			.create({
				deviceCode: "dc",
				userCode: "BCDFGHJK",
				clientId: "tv",
				requestedScope: undefined,
				expiresAtMs: Date.now() + 60_000,
				intervalSeconds: 5,
			})
			.catch((err: unknown) => err);
		expect(refused).toBeInstanceOf(Error);
		expect(refused).not.toBeInstanceOf(DeviceCodeStoreError);
	});
});

describe("makeIoredisClients rateLimiterClient", () => {
	// The script returns `{count, pttl}` as one reply, PTTL read inside the
	// script after the increment, so the pair describes a single counter
	// state — a separate PTTL round-trip could observe a key the window had
	// already expired out from under.
	it("incrementWithTtlAndPttl evaluates the script once and returns the {count, pttl} pair", async () => {
		const io = makeFakeIoredis({ eval: vi.fn().mockResolvedValue([3, 45_000]) });
		const c = makeIoredisClients(io);

		await expect(
			c.rateLimiterClient.incrementWithTtlAndPttl?.("token:ip:1.2.3.4", 60),
		).resolves.toEqual({ count: 3, pttl: 45_000 });

		const fake = io as unknown as { eval: ReturnType<typeof vi.fn> };
		expect(fake.eval).toHaveBeenCalledTimes(1);
		expect(fake.eval.mock.calls[0]?.[0]).toMatch(/PTTL/);
		expect(fake.eval.mock.calls[0]?.slice(1)).toEqual([1, "token:ip:1.2.3.4", "60"]);
	});

	it("incrementWithTtl still answers the bare count, off the same script", async () => {
		const io = makeFakeIoredis({ eval: vi.fn().mockResolvedValue([3, 45_000]) });
		const c = makeIoredisClients(io);

		await expect(c.rateLimiterClient.incrementWithTtl("token:ip:1.2.3.4", 60)).resolves.toBe(3);
	});
});

// ---------------------------------------------------------------------------
// The consent stores' scripts go through the same shared runner. What is
// pinned here is what a fake can see: which keys each script declares to
// Cluster, and that the caller's clock — not the server's — is what it is
// handed. Atomicity and the scripts' behaviour are pinned against a real Redis
// in `consent-store.test.mts`.
// ---------------------------------------------------------------------------

describe("makeIoredisClients consent clients — keys declared and the caller's clock", () => {
	const pendingKeys = {
		recordKeyPrefix: "consent:{pending}:ch:",
		sessionKeyPrefix: "consent:{pending}:sess:",
	};

	const lastScriptCall = (io: Redis): unknown[] => {
		const fake = io as unknown as Record<string, ReturnType<typeof vi.fn>>;
		return [...(fake.eval?.mock.calls ?? []), ...(fake.evalsha?.mock.calls ?? [])].at(
			-1,
		) as unknown[];
	};

	it("declares the record key and the session's index when parking a request", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { pendingConsentStoreClient } = makeIoredisClients(io);
		await pendingConsentStoreClient.set(pendingKeys, {
			challenge: "ch",
			sessionId: "sess",
			expiresAt: 601_000,
			nowMs: 1_000,
			ttlMs: 900_000,
			record: "{}",
			perSessionLimit: 16,
		});
		const call = lastScriptCall(io);
		expect(call.slice(1, 5)).toEqual([
			2,
			"consent:{pending}:ch:ch",
			"consent:{pending}:sess:sess",
			"1000",
		]);
	});

	it("declares only the record key on consume, reaching the index through the shared tag", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(null),
			eval: vi.fn().mockResolvedValue(null),
		});
		const { pendingConsentStoreClient } = makeIoredisClients(io);
		expect(await pendingConsentStoreClient.consume(pendingKeys, "ch", 2_000)).toBeNull();
		expect(lastScriptCall(io).slice(1, 4)).toEqual([1, "consent:{pending}:ch:ch", "2000"]);
	});

	it("hands the grant script the caller's clock and no expiry for a consent until revoked", async () => {
		const io = makeFakeIoredis({
			evalsha: vi.fn().mockResolvedValue(1),
			eval: vi.fn().mockResolvedValue(1),
		});
		const { consentStoreClient } = makeIoredisClients(io);
		await consentStoreClient.grant("consent:rec:1:u|1:c", {
			nowMs: 3_000,
			scopes: ["read"],
			grantedAt: 3_000,
			expiry: undefined,
		});
		expect(lastScriptCall(io).slice(1)).toEqual([
			1,
			"consent:rec:1:u|1:c",
			"3000",
			"3000",
			'["read"]',
			"",
			"",
		]);
	});
});

// ---------------------------------------------------------------------------
// The lock release, the subject sweep and the revocation record's write take
// the same EVALSHA-first path: a cold cache is recovered by EVAL of the text
// EVALSHA named, and anything that is not NOSCRIPT is the caller's error.
// `reply` is what Redis answers, `answer` what the client returns.
// ---------------------------------------------------------------------------

const sha1 = (text: string): string => createHash("sha1").update(text).digest("hex");
const noScript = (): Error => new Error("NOSCRIPT No matching script. Please use EVAL.");

describe("makeIoredisClients session-store scripts — EVALSHA-first with NOSCRIPT fallback", () => {
	const scripts = [
		{
			name: "federationTokenStoreClient.compareAndDelete",
			reply: 1,
			answer: true,
			run: (io: Redis) =>
				makeIoredisClients(io).federationTokenStoreClient.compareAndDelete("k", "v"),
			wire: [1, "k", "v"],
		},
		{
			name: "subjectSessionIndexClient.pruneExpiredAndList",
			reply: ["sid-1"],
			answer: ["sid-1"],
			run: (io: Redis) =>
				makeIoredisClients(io).subjectSessionIndexClient.pruneExpiredAndList("idx"),
			wire: [1, "idx"],
		},
		{
			name: "subjectRevocationClient.advanceRevocationBoundaries",
			reply: ["stored", "5000"],
			answer: { value: "stored", serverNowMs: 5_000 },
			run: (io: Redis) =>
				makeIoredisClients(io).subjectRevocationClient.advanceRevocationBoundaries("rev", "all", {
					beforeMs: 1_000,
					expiresAtMs: 2_000,
					grantRetentionMs: 3_000,
					skewMs: 4_000,
				}),
			wire: [1, "rev", "all", "1000", "2000", "3000", "4000"],
		},
	] as const;

	it.each(scripts)(
		"$name: NOSCRIPT on EVALSHA loads the named text by EVAL and re-warms the cache",
		async ({ reply, answer, run, wire }) => {
			const io = makeFakeIoredis({
				evalsha: vi.fn().mockResolvedValue(reply),
				eval: vi.fn().mockResolvedValue(reply),
			});
			// Warmup: whatever the script's residency flag was, it ends true.
			await run(io);
			io.eval.mockClear();
			io.evalsha.mockReset().mockRejectedValueOnce(noScript()).mockResolvedValue(reply);

			expect(await run(io)).toEqual(answer);
			expect(io.evalsha).toHaveBeenCalledTimes(1);
			expect(io.eval).toHaveBeenCalledTimes(1);
			const [sha, ...shaWire] = io.evalsha.mock.calls[0] as [string, ...unknown[]];
			const [text, ...evalWire] = io.eval.mock.calls[0] as [string, ...unknown[]];
			expect(sha1(text)).toBe(sha);
			expect(shaWire).toEqual(wire);
			expect(evalWire).toEqual(wire);

			expect(await run(io)).toEqual(answer);
			expect(io.evalsha).toHaveBeenCalledTimes(2);
			expect(io.eval).toHaveBeenCalledTimes(1);
		},
	);

	it.each(scripts)(
		"$name: a non-NOSCRIPT error from EVALSHA propagates, with no EVAL",
		async ({ reply, run }) => {
			const io = makeFakeIoredis({
				evalsha: vi.fn().mockResolvedValue(reply),
				eval: vi.fn().mockResolvedValue(reply),
			});
			await run(io);
			io.eval.mockClear();
			io.evalsha.mockReset().mockRejectedValue(new Error("ECONNRESET: connection lost"));

			await expect(run(io)).rejects.toThrow(/ECONNRESET/);
			expect(io.eval).not.toHaveBeenCalled();
		},
	);
});

// ---------------------------------------------------------------------------
// A replica names a script by the SHA-1 of its own text, and a cold cache —
// another replica's build, a SCRIPT FLUSH, a failover — loads that text. The
// text is the script's source: what its comments say is part of what ships.
// ---------------------------------------------------------------------------

describe("makeIoredisClients subjectRevocationClient — one write, the clamped one", () => {
	it("offers only the read and the clamped write", () => {
		const client = makeIoredisClients(makeFakeIoredis()).subjectRevocationClient;
		expect(Object.keys(client).sort()).toEqual(["advanceRevocationBoundaries", "get"]);
	});
});

describe("makeIoredisFederationGrantStoreClient — a cold cache loads this build's script text", () => {
	const writes = [
		{
			name: "replaceCredentials",
			run: (client: FederationGrantStoreClient) =>
				client.replaceCredentials("g", "c", {
					nowMs: 1_000,
					expectedVersion: 1,
					credential: "sealed",
					ineligible: null,
				}),
		},
		{
			name: "revoke",
			run: (client: FederationGrantStoreClient) =>
				client.revoke("g", "c", { atMs: 1_000, by: "user" }),
		},
		{
			name: "noteRefreshFailure",
			run: (client: FederationGrantStoreClient) =>
				client.noteRefreshFailure("g", {
					nowMs: 1_000,
					expectedVersion: 1,
					atMs: 1_000,
					kind: "transient",
					rowMs: 60_000,
					retryAfterSeconds: undefined,
					upstreamCode: undefined,
				}),
		},
	] as const;

	it.each(writes)(
		"$name: EVAL after NOSCRIPT sends the text EVALSHA named, which carries no history",
		async ({ run }) => {
			const io = makeFakeIoredis({
				evalsha: vi.fn().mockResolvedValue([0]),
				eval: vi.fn().mockResolvedValue([0]),
			});
			const client = makeIoredisFederationGrantStoreClient(io);
			await run(client);
			io.eval.mockClear();
			io.evalsha.mockReset().mockRejectedValueOnce(noScript()).mockResolvedValue([0]);

			expect(await run(client)).toBeNull();
			expect(io.evalsha).toHaveBeenCalledTimes(1);
			expect(io.eval).toHaveBeenCalledTimes(1);
			const [sha] = io.evalsha.mock.calls[0] as [string];
			const [text] = io.eval.mock.calls[0] as [string];
			expect(sha1(text)).toBe(sha);
			expect(text).not.toMatch(/#\d|\bD\d+\b|Copilot|Codex|reviewer/);
		},
	);
});
