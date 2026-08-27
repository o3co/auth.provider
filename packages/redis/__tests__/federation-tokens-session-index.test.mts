/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// #291 — logout must not walk the Redis keyspace.
//
// `removeBySid` used to be a `SCAN MATCH ft:<sid>:*` over the whole keyspace:
// O(number of keys in the database) work triggered by an end-user action, on
// the connection every other adapter shares. These tests pin the replacement:
// a per-session key index (`ft:idx:<sid>`) that makes the removal O(that
// session's federations), read in bounded batches, removed with `UNLINK`.
//
// They also pin the migration flag (`scanFallback`), which keeps the old scan
// as a safety net so that upgrading a live deployment does not orphan
// federation tokens written before the index existed.

import type { FederationTokens } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "../src/clients.mjs";
import {
	createRedisFederationTokenStore,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
} from "../src/federation-tokens.mjs";

/**
 * Fake modelling the two Redis types the store now uses: string keys for the
 * token envelopes and a SET key for the per-session index.
 */
function createFakeRedis() {
	const data = new Map<string, string>();
	const sets = new Map<string, Set<string>>();
	const ttls = new Map<string, number>();
	const removeKey = (k: string): number => {
		let removed = 0;
		if (data.delete(k)) removed += 1;
		if (sets.delete(k)) removed += 1;
		ttls.delete(k);
		return removed;
	};
	return {
		data,
		sets,
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
		del: vi.fn(async (...keys: string[]) => keys.reduce((n, k) => n + removeKey(k), 0)),
		unlink: vi.fn(async (...keys: string[]) => keys.reduce((n, k) => n + removeKey(k), 0)),
		sAddWithTtl: vi.fn(async (key: string, member: string, ttlMs: number) => {
			const members = sets.get(key) ?? new Set<string>();
			members.add(member);
			sets.set(key, members);
			// NX + GT semantics: never lower an existing deadline.
			ttls.set(key, Math.max(ttls.get(key) ?? 0, ttlMs));
		}),
		sRem: vi.fn(async (key: string, member: string) => {
			const members = sets.get(key);
			if (!members) return 0;
			const removed = members.delete(member) ? 1 : 0;
			if (members.size === 0) sets.delete(key);
			return removed;
		}),
		sScanIterator: vi.fn((key: string, _opts?: { COUNT?: number }) => {
			const snapshot = [...(sets.get(key) ?? [])];
			return (async function* () {
				for (const member of snapshot) yield member;
			})();
		}),
		scanIterator: vi.fn((opts: { MATCH: string; COUNT?: number }) => {
			const matchPrefix = opts.MATCH.endsWith("*") ? opts.MATCH.slice(0, -1) : opts.MATCH;
			const matched = [...data.keys()].filter((k) => k.startsWith(matchPrefix));
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
	} satisfies FederationTokenStoreClient & {
		data: Map<string, string>;
		sets: Map<string, Set<string>>;
		ttls: Map<string, number>;
	};
}

const tokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	expiresAt: new Date(Date.now() + 3600_000),
};

const plaintext = { mode: "allow-plaintext" } as const;

const indexMembers = (redis: ReturnType<typeof createFakeRedis>, sid: string): string[] =>
	[...(redis.sets.get(`ft:idx:${sid}`) ?? [])].sort();

describe("#291 — per-session federation key index", () => {
	it("attach records the federation name in the sid's index SET", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		expect(indexMembers(redis, "sid-1")).toEqual(["github", "google"]);
	});

	it("update records the federation name too (a store that only ever saw update stays indexed)", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		await store.update("sid-1", "google", tokens);
		expect(indexMembers(redis, "sid-1")).toEqual(["google"]);
	});

	it("the index key carries the store TTL, not the access-token expiry", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			ttl: 7200,
		});
		await store.attach("sid-1", "google", tokens);
		expect(redis.ttls.get("ft:idx:sid-1")).toBe(7200 * 1000);
	});

	it("the index key lives in the idx: sub-namespace, clear of the envelope keys", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		await store.attach("sid-1", "google", tokens);
		expect([...redis.sets.keys()]).toEqual(["ft:idx:sid-1"]);
		expect([...redis.data.keys()]).toEqual(["ft:sid-1:google"]);
	});

	it("delete(sid, name) drops the name from the index", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.delete("sid-1", "google");
		expect(indexMembers(redis, "sid-1")).toEqual(["github"]);
	});

	it("get() drops the name from the index when it self-heals a corrupt envelope", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		await store.attach("sid-1", "google", tokens);
		redis.data.set("ft:sid-1:google", "{not-json");
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(indexMembers(redis, "sid-1")).toEqual([]);
	});
});

describe("#291 — removeBySid is O(the session's federations)", () => {
	it("removes every indexed envelope without scanning the keyspace", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);

		await store.removeBySid("sid-1");

		expect(redis.scanIterator).not.toHaveBeenCalled();
		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
	});

	it("removes the index key itself", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		await store.attach("sid-1", "google", tokens);
		await store.removeBySid("sid-1");
		expect(redis.sets.has("ft:idx:sid-1")).toBe(false);
	});

	it("uses UNLINK, never DEL, for the removal", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		await store.attach("sid-1", "google", tokens);
		redis.del.mockClear();
		await store.removeBySid("sid-1");
		expect(redis.unlink).toHaveBeenCalled();
		expect(redis.del).not.toHaveBeenCalled();
	});

	it("reads the index in bounded batches — no unbounded fan-out on a heavily-linked session", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		for (let i = 0; i < 250; i++) {
			await store.attach("sid-big", `idp-${i}`, tokens);
		}
		redis.unlink.mockClear();

		await store.removeBySid("sid-big");

		// Every UNLINK stays within one batch; 250 envelopes cannot arrive as
		// one 250-argument command.
		for (const call of redis.unlink.mock.calls) {
			expect(call.length).toBeLessThanOrEqual(100);
		}
		expect(redis.unlink.mock.calls.length).toBeGreaterThanOrEqual(3);
		expect(redis.data.size).toBe(0);
	});

	it("is idempotent on a sid that was never attached", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		await expect(store.removeBySid("ghost")).resolves.toBeUndefined();
	});
});

describe("#291 — scanFallback migration flag", () => {
	it("defaults to enabled, so an upgrade still reaches tokens written before the index existed", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		// A pre-upgrade envelope: written by the previous release, so no index
		// member exists for it.
		redis.data.set(
			"ft:legacy-sid:google",
			JSON.stringify({ accessToken: "at", expiresAtMs: null }),
		);

		await store.removeBySid("legacy-sid");

		expect(redis.scanIterator).toHaveBeenCalled();
		expect(redis.data.has("ft:legacy-sid:google")).toBe(false);
	});

	it("scanFallback: false leaves pre-index envelopes behind — the flag is what makes the upgrade safe", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({
			client: redis,
			encryption: plaintext,
			scanFallback: false,
		});
		redis.data.set(
			"ft:legacy-sid:google",
			JSON.stringify({ accessToken: "at", expiresAtMs: null }),
		);

		await store.removeBySid("legacy-sid");

		expect(redis.data.has("ft:legacy-sid:google")).toBe(true);
	});

	it("the fallback also unlinks in bounded batches", async () => {
		const redis = createFakeRedis();
		const store = createRedisFederationTokenStore({ client: redis, encryption: plaintext });
		for (let i = 0; i < 250; i++) {
			redis.data.set(
				`ft:legacy-sid:idp-${i}`,
				JSON.stringify({ accessToken: "at", expiresAtMs: null }),
			);
		}

		await store.removeBySid("legacy-sid");

		for (const call of redis.unlink.mock.calls) {
			expect(call.length).toBeLessThanOrEqual(100);
		}
		expect(redis.data.size).toBe(0);
	});

	it("the builder forwards scanFallback", async () => {
		const redis = createFakeRedis();
		const store = redisFederationTokenStoreBuilder(
			{ client: redis, encryption: { mode: "allow-plaintext" }, scanFallback: false },
			{},
		);
		await store.attach("sid-1", "google", tokens);
		await store.removeBySid("sid-1");
		expect(redis.scanIterator).not.toHaveBeenCalled();
	});

	it("the module config schema exposes scanFallback, defaulting to true", () => {
		const parsed = redisFederationTokenStoreModule.configSchema?.safeParse({
			redisFederationTokenStore: {},
		});
		expect(parsed?.success).toBe(true);
		if (parsed?.success) {
			expect(parsed.data.redisFederationTokenStore.scanFallback).toBe(true);
		}
	});
});

describe("#291 — builder structural validator covers the index methods", () => {
	it.each(["unlink", "sAddWithTtl", "sRem", "sScanIterator"])(
		"rejects a client missing %s",
		(method) => {
			const client = createFakeRedis() as unknown as Record<string, unknown>;
			delete client[method];
			expect(() =>
				redisFederationTokenStoreBuilder({ client, encryption: { mode: "allow-plaintext" } }, {}),
			).toThrow(new RegExp(`missing required method.*${method}`));
		},
	);
});
