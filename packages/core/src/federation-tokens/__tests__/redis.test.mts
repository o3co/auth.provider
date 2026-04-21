/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createRedisFederationTokenStore, type RedisLikeClient } from "../adapters/redis.mjs";
import type { FederationTokens } from "../types.mjs";

function createFakeRedis() {
	const data = new Map<string, string>();
	const ttls = new Map<string, number>();
	return {
		data,
		ttls,
		get: vi.fn(async (k: string) => data.get(k) ?? null),
		set: vi.fn(async (k: string, v: string, opts?: { PX?: number }) => {
			data.set(k, v);
			if (opts?.PX !== undefined) ttls.set(k, opts.PX);
			return "OK";
		}),
		del: vi.fn(async (...keys: string[]) => {
			let n = 0;
			for (const k of keys) if (data.delete(k)) n += 1;
			return n;
		}),
		keys: vi.fn(async (pattern: string) => {
			const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
			return [...data.keys()].filter((k) => k.startsWith(prefix));
		}),
	} satisfies RedisLikeClient & { data: Map<string, string>; ttls: Map<string, number> };
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
		expect(round?.expiresAt.getTime()).toBe(accessTokenExpiry.getTime());
	});
});
