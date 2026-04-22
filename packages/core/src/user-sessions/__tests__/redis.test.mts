/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createRedisUserSessionStore } from "../adapters/redis.mjs";
import type { UserSessionStoreBase } from "../types.mjs";

// Minimal Redis client mock — matches the subset of the real client the adapter uses.
function createFakeRedis() {
	const data = new Map<string, { value: string; px?: number; addedAt: number }>();
	return {
		data,
		get: vi.fn(async (k: string) => {
			const entry = data.get(k);
			if (!entry) return null;
			if (entry.px && Date.now() - entry.addedAt > entry.px) {
				data.delete(k);
				return null;
			}
			return entry.value;
		}),
		set: vi.fn(async (k: string, v: string, opts?: { PX?: number; NX?: boolean }) => {
			if (opts?.NX && data.has(k)) return null;
			data.set(k, { value: v, px: opts?.PX, addedAt: Date.now() });
			return "OK";
		}),
		del: vi.fn(async (k: string) => {
			return data.delete(k) ? 1 : 0;
		}),
	};
}

describe("redis UserSessionStore", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	let store: UserSessionStoreBase;
	const base = {
		sid: "sid-1",
		sub: "u",
		authTime: new Date("2026-04-21"),
		expiresAt: new Date(Date.now() + 3600_000),
		claims: { email: "a@b.com" },
	};

	beforeEach(() => {
		redis = createFakeRedis();
		store = createRedisUserSessionStore({
			client: redis as unknown as Parameters<typeof createRedisUserSessionStore>[0]["client"],
			keyPrefix: "us:",
		});
	});

	it("kind is 'redis'", () => {
		expect(store.kind).toBe("redis");
	});

	it("create writes to Redis with PX = expiresAt - now (±1s)", async () => {
		await store.create(base);
		expect(redis.set).toHaveBeenCalledWith(
			"us:sid-1",
			expect.any(String),
			expect.objectContaining({ PX: expect.any(Number), NX: true }),
		);
		expect(redis.set.mock.calls).toHaveLength(1);
		const [, , opts] = redis.set.mock.calls[0] ?? [];
		const expected = base.expiresAt.getTime() - Date.now();
		expect(opts?.PX).toBeGreaterThan(expected - 2000);
		expect(opts?.PX).toBeLessThanOrEqual(expected + 100);
	});

	it("create throws on duplicate sid (NX failure)", async () => {
		await store.create(base);
		await expect(store.create(base)).rejects.toThrow(/already exists/);
	});

	it("get returns null for missing sid", async () => {
		expect(await store.get("missing")).toBeNull();
	});

	it("get roundtrips dates", async () => {
		await store.create(base);
		const s = await store.get("sid-1");
		expect(s?.authTime).toEqual(base.authTime);
		expect(s?.expiresAt).toEqual(base.expiresAt);
		expect(s?.createdAt).toBeInstanceOf(Date);
	});

	it("registerRP mutates and re-writes with remaining TTL", async () => {
		await store.create(base);
		const before = redis.set.mock.calls.length;
		await store.registerRP("sid-1", { clientId: "rp-1", registeredAt: new Date() });
		expect(redis.set.mock.calls.length).toBeGreaterThan(before);
		const s = await store.get("sid-1");
		expect(s?.activeRPs).toHaveLength(1);
	});

	it("registerRP round-trips backchannelLogoutSessionRequired and frontchannelLogoutSessionRequired through JSON envelope", async () => {
		await store.create(base);
		await store.registerRP("sid-1", {
			clientId: "rp-flags",
			backchannelLogoutUri: "https://rp/bc",
			backchannelLogoutSessionRequired: false,
			frontchannelLogoutUri: "https://rp/fc",
			frontchannelLogoutSessionRequired: false,
			registeredAt: new Date(),
		});
		const s = await store.get("sid-1");
		const rp = s?.activeRPs[0];
		expect(rp?.backchannelLogoutSessionRequired).toBe(false);
		expect(rp?.frontchannelLogoutSessionRequired).toBe(false);
	});

	it("delete removes the key", async () => {
		await store.create(base);
		await store.delete("sid-1");
		expect(redis.del).toHaveBeenCalledWith("us:sid-1");
		expect(await store.get("sid-1")).toBeNull();
	});

	it("updateClaims merges", async () => {
		await store.create(base);
		await store.updateClaims("sid-1", { name: "Alice" });
		const s = await store.get("sid-1");
		expect(s?.claims).toEqual({ email: "a@b.com", name: "Alice" });
	});

	it("removeFederation is idempotent", async () => {
		await store.create({ ...base, federations: ["google"] });
		await store.removeFederation("sid-1", "google");
		await store.removeFederation("sid-1", "google");
		const s = await store.get("sid-1");
		expect(s?.federations).toEqual([]);
	});

	it("get() self-heals corrupt (non-JSON) payload by deleting the key", async () => {
		// Match the fakeRedis envelope shape ({ value, px, addedAt }).
		redis.data.set("us:corrupt", { value: "{not-json", addedAt: Date.now() });
		expect(await store.get("corrupt")).toBeNull();
		expect(redis.del).toHaveBeenCalledWith("us:corrupt");
		// Subsequent create with the same sid must succeed (previously NX would
		// fail with a misleading "already exists" error).
		await expect(store.create({ ...base, sid: "corrupt" })).resolves.toBeUndefined();
	});

	it("create rejects expiresAt in the past with a clear message (not 'already exists')", async () => {
		await expect(store.create({ ...base, expiresAt: new Date(Date.now() - 1000) })).rejects.toThrow(
			/expiresAt is in the past/,
		);
	});
});
