/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed `ConsentStore` and `PendingConsentStore` (#561) against the
 * shared conformance suites, on a real Redis.
 *
 * The suites move time with `vi.setSystemTime`, which cannot move the Redis
 * server's clock — so they pass only because the adapters judge expiry by the
 * record's timestamp against the caller's `Date.now()`, never by the key's
 * TTL. The cases below the suites pin what is Redis-specific: the key layout
 * the Cluster argument rests on, the TTL that is only a safety net, the
 * per-session index the bound is enforced through, and atomicity across two
 * connections rather than one pipelined socket.
 */

import type { PendingConsentRecord } from "@o3co/auth-provider-core";
import { PENDING_CONSENT_PER_SESSION_LIMIT } from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	CONSENT_EXPIRY_SLACK_MS,
	createRedisConsentStore,
	createRedisPendingConsentStore,
} from "#/consent-store.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { runConsentStoreContract } from "./adapters.consent-store.contract.mjs";
import { runPendingConsentStoreContract } from "./adapters.pending-consent-store.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;
/** A second connection, so the racing cases are not serialised by one socket's pipeline. */
let other: Redis;
let keyCounter = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	other = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	await raw?.quit();
	await other?.quit();
	await container?.stop();
});

/** Per-test prefix isolation, so no case sees another's records. */
const freshPrefix = (): string => {
	keyCounter += 1;
	return `consent:test-${keyCounter}:`;
};

const consentStoreAt = (keyPrefix: string, io: Redis = raw) =>
	createRedisConsentStore({ client: makeIoredisClients(io).consentStoreClient, keyPrefix });

const pendingStoreAt = (keyPrefix: string, io: Redis = raw) =>
	createRedisPendingConsentStore({
		client: makeIoredisClients(io).pendingConsentStoreClient,
		keyPrefix,
	});

runConsentStoreContract("redis", { create: async () => consentStoreAt(freshPrefix()) });
runPendingConsentStoreContract("redis", { create: async () => pendingStoreAt(freshPrefix()) });

const parked = (overrides: Partial<PendingConsentRecord> = {}): PendingConsentRecord => ({
	challenge: "ch-1",
	sessionId: "sess-1",
	sub: "u-1",
	clientId: "app",
	scopes: ["read"],
	grantedScopes: [],
	authorizeUrl: "https://issuer.example/oauth/authorize?client_id=app",
	redirectUri: "https://app.example/cb",
	createdAt: Date.now(),
	expiresAt: Date.now() + 600_000,
	...overrides,
});

describe("createRedisConsentStore — what is Redis-specific (#561)", () => {
	it('declares kind "redis"', () => {
		expect(consentStoreAt(freshPrefix()).kind).toBe("redis");
	});

	it("keeps one hash per subject and client, keyed by the length-prefixed pair", async () => {
		// A separator would let ("a|b", "c") and ("a", "b|c") share a key; the
		// length prefix the challenge and replay stores use cannot.
		const prefix = freshPrefix();
		const store = consentStoreAt(prefix);
		await store.grant({ sub: "a|b", clientId: "c", scopes: ["read"], grantedAt: 1 });
		await store.grant({ sub: "a", clientId: "b|c", scopes: ["write"], grantedAt: 2 });
		expect((await raw.keys(`${prefix}*`)).sort()).toEqual([
			`${prefix}rec:1:a|3:b|c`,
			`${prefix}rec:3:a|b|1:c`,
		]);
		expect(await raw.type(`${prefix}rec:3:a|b|1:c`)).toBe("hash");
		expect((await store.find("a|b", "c"))?.scopes).toEqual(["read"]);
		expect((await store.find("a", "b|c"))?.scopes).toEqual(["write"]);
	});

	it("records a consent until revoked with no TTL, and removes the one an earlier expiring grant set", async () => {
		// Left in place, the earlier grant's TTL would delete the new
		// until-revoked consent when it fired — silently, on no request.
		const prefix = freshPrefix();
		const store = consentStoreAt(prefix);
		const key = `${prefix}rec:3:u-1|3:app`;
		await store.grant({
			sub: "u-1",
			clientId: "app",
			scopes: ["read"],
			grantedAt: Date.now(),
			expiresAt: Date.now() + 60_000,
		});
		expect(await raw.pttl(key)).toBeGreaterThan(0);
		await store.grant({ sub: "u-1", clientId: "app", scopes: ["write"], grantedAt: Date.now() });
		expect(await raw.pttl(key)).toBe(-1);
	});

	it("gives an expiring consent a TTL past its expiry by the slack, as a safety net only", async () => {
		const prefix = freshPrefix();
		const store = consentStoreAt(prefix);
		const lifetime = 60_000;
		await store.grant({
			sub: "u-1",
			clientId: "app",
			scopes: ["read"],
			grantedAt: Date.now(),
			expiresAt: Date.now() + lifetime,
		});
		const pttl = await raw.pttl(`${prefix}rec:3:u-1|3:app`);
		expect(pttl).toBeGreaterThan(lifetime);
		expect(pttl).toBeLessThanOrEqual(lifetime + CONSENT_EXPIRY_SLACK_MS);
	});

	it("reclaims a record found past its expiry, though its TTL has not fired", async () => {
		const prefix = freshPrefix();
		const store = consentStoreAt(prefix);
		await store.grant({
			sub: "u-1",
			clientId: "app",
			scopes: ["read"],
			grantedAt: Date.now() - 10_000,
			expiresAt: Date.now() - 1,
		});
		expect(await raw.exists(`${prefix}rec:3:u-1|3:app`)).toBe(1);
		expect(await store.find("u-1", "app")).toBeNull();
		expect(await raw.exists(`${prefix}rec:3:u-1|3:app`)).toBe(0);
	});

	it("keeps every scope of many grants racing across two connections", async () => {
		// The union happens inside one script. As a read-modify-write across
		// round trips, grants interleaving on two sockets lose scopes.
		const prefix = freshPrefix();
		const stores = [consentStoreAt(prefix, raw), consentStoreAt(prefix, other)];
		const scopes = Array.from({ length: 40 }, (_, i) => `scope-${i}`);
		await Promise.all(
			scopes.map((scope, i) =>
				stores[i % 2]?.grant({ sub: "u-1", clientId: "app", scopes: [scope], grantedAt: i }),
			),
		);
		const found = await stores[0]?.find("u-1", "app");
		expect([...(found?.scopes ?? [])].sort()).toEqual([...scopes].sort());
	});
});

describe("createRedisPendingConsentStore — what is Redis-specific (#561)", () => {
	it('declares kind "redis"', () => {
		expect(pendingStoreAt(freshPrefix()).kind).toBe("redis");
	});

	it("keys the record and its session index under one shared hash tag", async () => {
		// `consume` arrives with the challenge alone and has to take the
		// request out of its session's index in the same script, so the two
		// keys must hash to the slot Cluster routed the script to. The tag is a
		// constant, so every parked request shares that slot.
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		await store.set(parked());
		expect((await raw.keys(`${prefix}*`)).sort()).toEqual([
			`${prefix}{pending}:ch:ch-1`,
			`${prefix}{pending}:sess:sess-1`,
		]);
		expect(await raw.type(`${prefix}{pending}:ch:ch-1`)).toBe("hash");
		expect(await raw.type(`${prefix}{pending}:sess:sess-1`)).toBe("zset");
	});

	it("gives the record a TTL past its expiry by the slack, and the index one no shorter", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		const lifetime = 600_000;
		await store.set(parked({ expiresAt: Date.now() + lifetime }));
		const recordTtl = await raw.pttl(`${prefix}{pending}:ch:ch-1`);
		expect(recordTtl).toBeGreaterThan(lifetime);
		expect(recordTtl).toBeLessThanOrEqual(lifetime + CONSENT_EXPIRY_SLACK_MS);
		// A shorter-lived request parked later must not shorten the index under
		// the longer-lived one already in it.
		await store.set(parked({ challenge: "ch-2", expiresAt: Date.now() + 1_000 }));
		expect(await raw.pttl(`${prefix}{pending}:sess:sess-1`)).toBeGreaterThanOrEqual(
			(await raw.pttl(`${prefix}{pending}:ch:ch-1`)) - 50,
		);
	});

	it("evicts past the per-session bound in Redis itself, record and index entry together", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		for (let i = 0; i <= PENDING_CONSENT_PER_SESSION_LIMIT; i += 1) {
			await store.set(parked({ challenge: `ch-${i}` }));
		}
		const index = `${prefix}{pending}:sess:sess-1`;
		expect(await raw.zcard(index)).toBe(PENDING_CONSENT_PER_SESSION_LIMIT);
		expect(await raw.zscore(index, "ch-0")).toBeNull();
		expect(await raw.exists(`${prefix}{pending}:ch:ch-0`)).toBe(0);
		expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(1);
	});

	it("takes a consumed request out of its session's index in the same step", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		await store.set(parked());
		await store.set(parked({ challenge: "ch-2" }));
		expect(await store.consume("ch-1")).not.toBeNull();
		expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(0);
		expect(await raw.zrange(`${prefix}{pending}:sess:sess-1`, 0, -1)).toEqual(["ch-2"]);
	});

	it("reads without spending, and reclaims a record read past its expiry", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		await store.set(parked());
		await store.set(parked({ challenge: "ch-old", expiresAt: Date.now() - 1 }));
		expect(await store.get("ch-1")).not.toBeNull();
		expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(1);
		expect(await store.get("ch-old")).toBeNull();
		expect(await raw.exists(`${prefix}{pending}:ch:ch-old`)).toBe(0);
		expect(await raw.zrange(`${prefix}{pending}:sess:sess-1`, 0, -1)).toEqual(["ch-1"]);
	});

	it("moves a challenge re-parked by another session out of the first session's index", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		await store.set(parked({ sessionId: "sess-a" }));
		await store.set(parked({ sessionId: "sess-b" }));
		expect(await raw.exists(`${prefix}{pending}:sess:sess-a`)).toBe(0);
		expect(await raw.zrange(`${prefix}{pending}:sess:sess-b`, 0, -1)).toEqual(["ch-1"]);
		expect((await store.get("ch-1"))?.sessionId).toBe("sess-b");
	});

	it("hands a parked request to exactly one of many answers racing across two connections", async () => {
		// Two sockets, so the answers genuinely interleave at the server rather
		// than queueing behind one connection's pipeline.
		const prefix = freshPrefix();
		const stores = [pendingStoreAt(prefix, raw), pendingStoreAt(prefix, other)];
		await stores[0]?.set(parked());
		const answers = await Promise.all(
			Array.from({ length: 20 }, (_, i) => stores[i % 2]?.consume("ch-1")),
		);
		expect(answers.filter((answer) => answer !== null && answer !== undefined)).toHaveLength(1);
		expect(await raw.exists(`${prefix}{pending}:sess:sess-1`)).toBe(0);
	});

	it("keeps the stored record byte-for-byte, the characters JSON escapes included", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		const record = parked({
			scopes: ["read", "wrïte", "a/b", 'quote"d', "emoji-\u{1f510}"],
			state: "stäte\n ",
		});
		await store.set(record);
		expect(await store.consume("ch-1")).toEqual(record);
	});
});

describe("corrupt records read as absent, never as a throw or a half-typed record (#561 review)", () => {
	// Nothing this package writes is corrupt; a value edited by hand, restored
	// from a mismatched backup or written by another version is. A record that
	// is not the shape the port promises must not reach the consent route —
	// whose session binding calls `Buffer.from(pending.sessionId)` and would
	// throw — nor answer for a challenge other than the one looked up.
	const pendingCorruptions: ReadonlyArray<
		readonly [name: string, corrupt: (valid: Record<string, unknown>) => string]
	> = [
		["invalid JSON", () => "{not json"],
		["JSON that is not an object", (valid) => JSON.stringify([valid])],
		["a missing sessionId", ({ sessionId: _, ...rest }) => JSON.stringify(rest)],
		["a non-string sessionId", (valid) => JSON.stringify({ ...valid, sessionId: 42 })],
		["non-string scopes", (valid) => JSON.stringify({ ...valid, scopes: ["read", 5] })],
		[
			"grantedScopes that are not an array",
			(valid) => JSON.stringify({ ...valid, grantedScopes: "read" }),
		],
		["a non-string state", (valid) => JSON.stringify({ ...valid, state: { x: 1 } })],
		["a createdAt that is not a number", (valid) => JSON.stringify({ ...valid, createdAt: "now" })],
		["an expiresAt that is not a number", (valid) => JSON.stringify({ ...valid, expiresAt: null })],
		[
			"a challenge other than its key's",
			(valid) => JSON.stringify({ ...valid, challenge: "ch-2" }),
		],
	];

	/** Parks a valid request, then overwrites the stored JSON the way corruption would. */
	const parkCorrupt = async (
		prefix: string,
		corrupt: (valid: Record<string, unknown>) => string,
	) => {
		const store = pendingStoreAt(prefix);
		const valid = parked();
		await store.set(valid);
		await raw.hset(
			`${prefix}{pending}:ch:ch-1`,
			"record",
			corrupt(valid as unknown as Record<string, unknown>),
		);
		return store;
	};

	for (const [name, corrupt] of pendingCorruptions) {
		it(`get answers null for a parked request with ${name}, and reclaims it with its index entry`, async () => {
			const prefix = freshPrefix();
			const store = await parkCorrupt(prefix, corrupt);
			await expect(store.get("ch-1")).resolves.toBeNull();
			expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(0);
			expect(await raw.zscore(`${prefix}{pending}:sess:sess-1`, "ch-1")).toBeNull();
		});

		it(`consume answers null for a parked request with ${name}, and reclaims it with its index entry`, async () => {
			const prefix = freshPrefix();
			const store = await parkCorrupt(prefix, corrupt);
			await expect(store.consume("ch-1")).resolves.toBeNull();
			expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(0);
			expect(await raw.zscore(`${prefix}{pending}:sess:sess-1`, "ch-1")).toBeNull();
		});
	}

	it("does not let a record carrying another challenge answer for, or spend, that challenge's request", async () => {
		const prefix = freshPrefix();
		const store = pendingStoreAt(prefix);
		const second = parked({ challenge: "ch-2", clientId: "other" });
		await store.set(parked());
		await store.set(second);
		await raw.hset(`${prefix}{pending}:ch:ch-1`, "record", JSON.stringify(second));
		expect(await store.consume("ch-1")).toBeNull();
		expect(await store.get("ch-2")).toEqual(second);
	});

	it("reclaims a corrupt record only while it is still the one that was read", async () => {
		// The reclaim is a compare-and-delete: a request re-parked under the
		// challenge between the read and the reclaim is a valid record, and must
		// not be taken with the corrupt one it replaced.
		const prefix = freshPrefix();
		const client = makeIoredisClients(raw).pendingConsentStoreClient;
		const keys = {
			recordKeyPrefix: `${prefix}{pending}:ch:`,
			sessionKeyPrefix: `${prefix}{pending}:sess:`,
		};
		const store = pendingStoreAt(prefix);
		await store.set(parked());
		expect(await client.discard(keys, "ch-1", "{not what is stored")).toBe(false);
		expect(await store.get("ch-1")).not.toBeNull();
		const stored = (await raw.hget(`${prefix}{pending}:ch:ch-1`, "record")) as string;
		expect(await client.discard(keys, "ch-1", stored)).toBe(true);
		expect(await raw.exists(`${prefix}{pending}:ch:ch-1`)).toBe(0);
		expect(await raw.exists(`${prefix}{pending}:sess:sess-1`)).toBe(0);
	});

	const consentCorruptions: ReadonlyArray<readonly [name: string, fields: Record<string, string>]> =
		[
			["scopes that are not JSON", { scopes: "read write" }],
			["scopes that are not an array", { scopes: '{"0":"read"}' }],
			["non-string scopes", { scopes: '["read",5]' }],
			["a grantedAt that is not a number", { grantedAt: "yesterday" }],
			["an empty grantedAt", { grantedAt: "" }],
		];

	for (const [name, fields] of consentCorruptions) {
		it(`find answers null for a consent record with ${name}`, async () => {
			const prefix = freshPrefix();
			const store = consentStoreAt(prefix);
			await store.grant({ sub: "u-1", clientId: "app", scopes: ["read"], grantedAt: 1 });
			await raw.hset(`${prefix}rec:3:u-1|3:app`, fields);
			await expect(store.find("u-1", "app")).resolves.toBeNull();
		});
	}

	it("lets nothing of a corrupt consent record into the next grant's union", async () => {
		// What `find` reports absent must not contribute scopes either: the user
		// is asked again, and what they answer is the whole record.
		const prefix = freshPrefix();
		const store = consentStoreAt(prefix);
		await store.grant({ sub: "u-1", clientId: "app", scopes: ["read"], grantedAt: 1 });
		await raw.hset(`${prefix}rec:3:u-1|3:app`, { scopes: '["admin",5]' });
		expect(await store.find("u-1", "app")).toBeNull();
		await store.grant({ sub: "u-1", clientId: "app", scopes: ["write"], grantedAt: 2 });
		expect(await store.find("u-1", "app")).toEqual({
			sub: "u-1",
			clientId: "app",
			scopes: ["write"],
			grantedAt: 2,
		});
	});
});
