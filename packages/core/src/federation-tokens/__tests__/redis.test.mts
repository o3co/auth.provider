/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it, beforeEach, vi } from "vitest";
import { createRedisFederationTokenStore, type RedisLikeClient } from "../adapters/redis.mjs";
import type { FederationTokens } from "../types.mjs";

function createFakeRedis() {
	const data = new Map<string, string>();
	return {
		data,
		get: vi.fn(async (k: string) => data.get(k) ?? null),
		set: vi.fn(async (k: string, v: string) => {
			data.set(k, v);
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
	} satisfies RedisLikeClient & { data: Map<string, string> };
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
		const raw = [...redis.data.values()][0]!;
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
		const raw = [...redis.data.values()][0]!;
		expect(raw).toContain("rt-secret");
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});
});
