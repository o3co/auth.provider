/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "../src/clients.mjs";
import { createRedisFederationTokenStore } from "../src/federation-tokens.mjs";

function createFakeRedis() {
	const data = new Map<string, string>();
	const ttls = new Map<string, number>();
	return {
		data,
		ttls,
		get: vi.fn(async (k: string) => data.get(k) ?? null),
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
		compareAndDelete: vi.fn(async (k: string, expected: string): Promise<boolean> => {
			const stored = data.get(k);
			if (stored !== undefined && stored === expected) {
				data.delete(k);
				return true;
			}
			return false;
		}),
	} satisfies FederationTokenStoreClient & { data: Map<string, string>; ttls: Map<string, number> };
}

const encryptionKey = Buffer.alloc(32, 7);
const tokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	idToken: "it",
	expiresAt: new Date(Date.now() + 3600_000),
};

describe("AS-3: redis FederationTokenStore.deleteBySession → removeBySid (BREAKING rename)", () => {
	it("redis store exposes removeBySid", () => {
		const store = createRedisFederationTokenStore({
			client: createFakeRedis(),
			encryption: { mode: "required", key: encryptionKey },
		});
		expect("removeBySid" in store).toBe(true);
	});

	it("redis store no longer exposes deleteBySession", () => {
		const store = createRedisFederationTokenStore({
			client: createFakeRedis(),
			encryption: { mode: "required", key: encryptionKey },
		});
		expect("deleteBySession" in store).toBe(false);
	});

	it("removeBySid removes all federation entries for sid (functional parity)", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: { mode: "required", key: encryptionKey },
		});
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("removeBySid is idempotent on absent sid (parity with in-memory adapter)", async () => {
		const store = createRedisFederationTokenStore({
			client: createFakeRedis(),
			encryption: { mode: "required", key: encryptionKey },
		});
		await expect(store.removeBySid("nope")).resolves.toBeUndefined();
	});
});
