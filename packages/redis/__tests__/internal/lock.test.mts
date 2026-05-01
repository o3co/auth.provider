/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it, vi } from "vitest";
import { createRedisLock, type RedisLockClient } from "../../src/internal/lock.mjs";

function makeFakeRedis(): RedisLockClient & {
	data: Map<string, string>;
	set: ReturnType<typeof vi.fn>;
} {
	const data = new Map<string, string>();
	const set = vi.fn(async (key: string, value: string, opts?: { PX?: number; NX?: boolean }) => {
		if (opts?.NX && data.has(key)) return null;
		data.set(key, value);
		return "OK";
	});
	return {
		data,
		set,
		get: async (key: string) => data.get(key) ?? null,
		del: async (key: string) => (data.delete(key) ? 1 : 0),
	};
}

describe("redis FederationToken lock", () => {
	it("SET NX PX acquires when key absent", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake, keyPrefix: "ftlock:" });
		const r = await lock.acquireLock({ sid: "s", federationName: "google" });
		expect(r.acquired).toBe(true);
		expect(fake.set).toHaveBeenCalledWith(
			"ftlock:s:google",
			expect.any(String),
			expect.objectContaining({ NX: true, PX: expect.any(Number) }),
		);
		if (r.acquired) await r.release();
	});

	it("returns acquired: false (timeout) when NX fails up to waitForMs", async () => {
		const fake = makeFakeRedis();
		fake.data.set("ftlock:s:google", "other-owner");
		const lock = createRedisLock({ client: fake, keyPrefix: "ftlock:" });
		const r = await lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 100 });
		expect(r.acquired).toBe(false);
		if (!r.acquired) expect(r.reason).toBe("timeout");
	});

	it("release deletes the key when stored value matches", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake, keyPrefix: "ftlock:" });
		const r = await lock.acquireLock({ sid: "s", federationName: "google" });
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
		expect(fake.data.has("ftlock:s:google")).toBe(false);
	});

	it("release does NOT delete the key when another owner stole the lock (compare-and-delete)", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake, keyPrefix: "ftlock:" });
		const r = await lock.acquireLock({ sid: "s", federationName: "google" });
		expect(r.acquired).toBe(true);
		fake.data.set("ftlock:s:google", "stolen-by-other-process");
		if (r.acquired) await r.release();
		expect(fake.data.has("ftlock:s:google")).toBe(true);
		expect(fake.data.get("ftlock:s:google")).toBe("stolen-by-other-process");
	});

	it("default keyPrefix is 'ftlock:' when not specified", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake });
		await lock.acquireLock({ sid: "s", federationName: "google" });
		expect(fake.set).toHaveBeenCalledWith(
			"ftlock:s:google",
			expect.any(String),
			expect.any(Object),
		);
	});

	it("separate (sid, federationName) pairs don't block each other", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake });
		const a = await lock.acquireLock({ sid: "s1", federationName: "google" });
		const b = await lock.acquireLock({ sid: "s1", federationName: "github", waitForMs: 100 });
		const c = await lock.acquireLock({ sid: "s2", federationName: "google", waitForMs: 100 });
		expect(a.acquired).toBe(true);
		expect(b.acquired).toBe(true);
		expect(c.acquired).toBe(true);
		if (a.acquired) await a.release();
		if (b.acquired) await b.release();
		if (c.acquired) await c.release();
	});

	it("second acquirer waits until first releases (NX contention path)", async () => {
		const fake = makeFakeRedis();
		const lock = createRedisLock({ client: fake });
		const a = await lock.acquireLock({ sid: "s", federationName: "google", ttlMs: 5_000 });
		expect(a.acquired).toBe(true);
		const bPromise = lock.acquireLock({ sid: "s", federationName: "google", waitForMs: 500 });
		setTimeout(() => {
			if (a.acquired) a.release();
		}, 100);
		const b = await bPromise;
		expect(b.acquired).toBe(true);
		if (b.acquired) await b.release();
	});
});
