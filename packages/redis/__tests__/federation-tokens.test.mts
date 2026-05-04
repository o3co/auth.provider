/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type FederationTokenStoreBase,
	type FederationTokens,
	type SupportsLock,
	supportsLock,
} from "@o3co/auth-provider-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "../src/clients.mjs";
import { createRedisFederationTokenStore } from "../src/federation-tokens.mjs";

function createFakeRedis() {
	const data = new Map<string, string>();
	const ttls = new Map<string, number>();
	return {
		data,
		ttls,
		get: vi.fn(async (k: string) => data.get(k) ?? null),
		// Positional form: (key, value, mode: "PX", ttlMs, condition?: "NX")
		set: vi.fn(
			async (
				k: string,
				v: string,
				_mode: "PX",
				ttl: number,
				condition?: "NX",
			): Promise<"OK" | null> => {
				if (condition === "NX" && data.has(k)) return null;
				data.set(k, v);
				ttls.set(k, ttl);
				return "OK";
			},
		),
		del: vi.fn(async (...keys: string[]) => {
			let n = 0;
			for (const k of keys) if (data.delete(k)) n += 1;
			return n;
		}),
		scanIterator: vi.fn((opts: { MATCH: string; COUNT?: number }) => {
			const prefix = opts.MATCH.endsWith("*") ? opts.MATCH.slice(0, -1) : opts.MATCH;
			const matched = [...data.keys()].filter((k) => k.startsWith(prefix));
			return (async function* () {
				for (const k of matched) yield k;
			})();
		}),
	} satisfies FederationTokenStoreClient & { data: Map<string, string>; ttls: Map<string, number> };
}

const encryptionKey = Buffer.alloc(32, 7);
const tokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	idToken: "it",
	expiresAt: new Date(Date.now() + 3600_000),
};

describe("redis FederationTokenStore (encryption = required)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("kind is 'redis'", () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		expect(store.kind).toBe("redis");
	});

	it("attach encrypts refreshToken at rest", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).not.toContain("rt-secret");
		// round-trip
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("deleteBySession removes all federations for sid", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.deleteBySession("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("missing encryption key throws at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "required", key: Buffer.alloc(0) },
			}),
		).toThrow(/encryption key/i);
	});

	it("rejects ttl: 0 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: 0,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: -1 at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: -1,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: NaN at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: Number.NaN,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});

	it("rejects ttl: Infinity at construction", () => {
		expect(() =>
			createRedisFederationTokenStore({
				client: redis,
				encryption: { mode: "allow-plaintext" },
				ttl: Number.POSITIVE_INFINITY,
			}),
		).toThrow(/ttl must be a positive finite number/i);
	});
});

describe("redis FederationTokenStore (encryption = allow-plaintext)", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("attach stores refreshToken in clear (opt-in)", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-1", "google", tokens);
		const values = [...redis.data.values()];
		expect(values).toHaveLength(1);
		const raw = values[0] as string;
		expect(raw).toContain("rt-secret");
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("get() self-heals corrupt JSON by deleting the key (Copilot round 3 #5)", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		redis.data.set("ft:sid-1:google", "{not-json");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(redis.del).toHaveBeenCalledWith("ft:sid-1:google");
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});

	it("get() self-heals when decryption fails (wrong / rotated encryption key)", async () => {
		const keyA = Buffer.alloc(32, 1);
		const keyB = Buffer.alloc(32, 2);
		// Encrypt with keyA, try to read with keyB.
		const writer = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: keyA },
		});
		await writer.attach("sid-1", "google", tokens);
		const reader = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: keyB },
		});
		expect(await reader.get("sid-1", "google")).toBeNull();
		// The corrupt key is now gone so the next get also returns null naturally.
		expect(redis.data.has("ft:sid-1:google")).toBe(false);
	});
});

describe("redis FederationTokenStore implements SupportsLock", () => {
	it("supportsLock returns true for the redis store", () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		expect(supportsLock(store)).toBe(true);
	});

	it("acquireLock returns acquired: true and release cleans up", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		const r = await (store as FederationTokenStoreBase & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		if (r.acquired) await r.release();
		// After release the lock key is gone (uses lock: namespace, not ft: namespace).
		const lockKeys = [...redis.data.keys()].filter((k) => k.includes("lock:"));
		expect(lockKeys).toHaveLength(0);
	});

	it("lock key uses the lock: sub-namespace, not the token envelope namespace", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("s", "google", {
			accessToken: "at",
			expiresAt: new Date(Date.now() + 3600_000),
		});
		const r = await (store as FederationTokenStoreBase & SupportsLock).acquireLock({
			sid: "s",
			federationName: "google",
		});
		expect(r.acquired).toBe(true);
		// The lock key contains "lock:" and the token envelope key does not.
		const lockKeys = [...redis.data.keys()].filter((k) => k.includes("lock:"));
		const tokenKeys = [...redis.data.keys()].filter((k) => !k.includes("lock:"));
		expect(lockKeys).toHaveLength(1);
		expect(tokenKeys).toHaveLength(1);
		expect(lockKeys[0]).toContain("ft:lock:");
		expect(tokenKeys[0]).toMatch(/^ft:s:google$/);
		if (r.acquired) await r.release();
	});
});

describe("redis FederationTokenStore TTL is independent of access_token expiry", () => {
	let redis: ReturnType<typeof createFakeRedis>;
	beforeEach(() => {
		redis = createFakeRedis();
	});

	it("default TTL (24h) is used regardless of tokens.expiresAt", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		// Access token expires in 1 hour, but the record must live long enough
		// for the refresh_token to be usable after that.
		const shortLivedAT: FederationTokens = {
			accessToken: "at",
			refreshToken: "rt",
			expiresAt: new Date(Date.now() + 3600_000),
		};
		await store.attach("sid-1", "google", shortLivedAT);
		const ttl = redis.ttls.get("ft:sid-1:google");
		expect(ttl).toBe(86400 * 1000); // 24h in ms, NOT 1h
	});

	it("custom TTL option is honored", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
			ttl: 7200, // 2h
		});
		await store.attach("sid-1", "google", tokens);
		expect(redis.ttls.get("ft:sid-1:google")).toBe(7200 * 1000);
	});

	it("access token expiresAt is preserved in the envelope for consumer refresh decisions", async () => {
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		const accessTokenExpiry = new Date(Date.now() + 1800_000); // 30min
		await store.attach("sid-1", "google", { ...tokens, expiresAt: accessTokenExpiry });
		const round = await store.get("sid-1", "google");
		expect(round?.expiresAt).toBeInstanceOf(Date);
		expect((round?.expiresAt as Date).getTime()).toBe(accessTokenExpiry.getTime());
	});

	it("expiresAt=null round-trips as null (GitHub OAuth Apps classic)", async () => {
		// Regression: FederationTokens.expiresAt is `Date | null` (required).
		// `null` MUST persist as `null` in the envelope and deserialize back to `null`,
		// so F-6 refresh logic can reliably detect "no finite expiry" without falling
		// through to a Date-instanceof check that would silently convert to
		// `new Date(null)` === epoch.
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "allow-plaintext" },
		});
		await store.attach("sid-gh", "github", { ...tokens, expiresAt: null });
		const round = await store.get("sid-gh", "github");
		expect(round?.expiresAt).toBeNull();
	});
});
