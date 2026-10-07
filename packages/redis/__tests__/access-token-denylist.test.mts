/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed AccessTokenDenylist. A revocation on one replica must be
 * visible on the others; the memory denylist forks per replica, so
 * `core.deployment.mode = "multi"` refuses it (core's replica-safety guard).
 */
import type { AccessTokenDenylist } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createRedisAccessTokenDenylist,
	redisAccessTokenDenylistBuilder,
	redisAccessTokenDenylistModule,
} from "#/access-token-denylist.mjs";
import type { AccessTokenDenylistClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { relativeDeadline, serverPasses, testRedis } from "./support/redis.mjs";

let client: Redis;
let denylistClient: AccessTokenDenylistClient;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	client = new Redis(at);
	denylistClient = makeIoredisClients(client).accessTokenDenylistClient;
});

afterAll(async () => {
	await client?.quit();
});

function freshStore(): Promise<AccessTokenDenylist> {
	keyCounter += 1;
	return createRedisAccessTokenDenylist({
		client: denylistClient,
		keyPrefix: `atdeny:test-${keyCounter}:`,
	});
}

describe("createRedisAccessTokenDenylist", () => {
	it('declares kind "redis"', async () => {
		expect((await freshStore()).kind).toBe("redis");
	});

	it("has() is false for a jti nobody revoked", async () => {
		expect(await (await freshStore()).has("never-added")).toBe(false);
	});

	it("has() is true after add()", async () => {
		const store = await freshStore();
		await store.add("j1", Date.now() + 60_000);
		expect(await store.has("j1")).toBe(true);
	});

	it("stops answering true once the token's own exp passes", async () => {
		// The entry's TTL is the access token's remaining lifetime: past that the
		// token fails verification on its `exp` anyway, so keeping the jti would
		// only grow the keyspace forever.
		//
		// Waited out to the latest instant the key can live to on the server's
		// clock (`relativeDeadline`): its PX runs from when the SET reached the
		// server, not from the host's call.
		const store = await freshStore();
		const exp = Date.now() + 1_000;
		const end = await relativeDeadline(
			() => client,
			() => store.add("j2", exp),
			(before) => exp - before,
		);
		expect(await store.has("j2")).toBe(true);
		await serverPasses(() => client)(end);
		expect(await store.has("j2")).toBe(false);
	});

	it("last add() wins on the expiry", async () => {
		// Past the latest instant the first add's key could have lived to, on
		// the server's clock, the jti is still denied: the second add's expiry
		// is the one in force.
		const store = await freshStore();
		const first = Date.now() + 1_000;
		const firstEnd = await relativeDeadline(
			() => client,
			() => store.add("j3", first),
			(before) => first - before,
		);
		await store.add("j3", Date.now() + 600_000);
		await serverPasses(() => client)(firstEnd);
		expect(await store.has("j3")).toBe(true);
	});

	it("accepts an already-expired token without writing anything", async () => {
		// RFC 7009 revocation of an expired AT is legal and idempotent, and the
		// route deliberately allows it (`ignoreExpiration: true`). `SET ... PX 0`
		// is a Redis error, so the write is skipped rather than attempted.
		const store = await freshStore();
		await expect(store.add("j-expired", Date.now() - 1_000)).resolves.toBeUndefined();
		expect(await store.has("j-expired")).toBe(false);
	});

	// The next two mirror core's contract cases, which this adapter cannot run
	// (its expiry is Redis's own key TTL, not the suite's fake clock).
	it("refuses an expiry that is not a finite number, and writes nothing", async () => {
		const store = await freshStore();
		for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			await expect(store.add("j-bad", bad)).rejects.toThrow(RangeError);
			expect(await store.has("j-bad")).toBe(false);
		}
	});

	it("accepts a fractional expiry — a non-integer JWT exp — rounding the key's life up", async () => {
		// `PX` takes whole milliseconds; a fractional value is a Redis error
		// (`ERR value is not an integer or out of range`), which the revoke
		// route would swallow — leaving the token unrevoked.
		const store = await freshStore();
		await store.add("j-frac", Date.now() + 60_000.5);
		expect(await store.has("j-frac")).toBe(true);
		const pttl = await client.pttl(`atdeny:test-${keyCounter}:j-frac`);
		expect(pttl).toBeGreaterThan(59_000);
	});

	it("namespaces keys by keyPrefix so two deployments do not share revocations", async () => {
		const a = await createRedisAccessTokenDenylist({
			client: denylistClient,
			keyPrefix: "atdeny:tenant-a:",
		});
		const b = await createRedisAccessTokenDenylist({
			client: denylistClient,
			keyPrefix: "atdeny:tenant-b:",
		});
		await a.add("shared-jti", Date.now() + 60_000);
		expect(await a.has("shared-jti")).toBe(true);
		expect(await b.has("shared-jti")).toBe(false);
	});
});

describe("redisAccessTokenDenylistBuilder", () => {
	it("refuses to build without a client instead of failing on first revocation", async () => {
		await expect(redisAccessTokenDenylistBuilder({ type: "redis" }, {})).rejects.toThrow(/client/);
	});

	it("builds when given a client", async () => {
		const store = await redisAccessTokenDenylistBuilder(
			{ type: "redis", client: denylistClient },
			{},
		);
		expect(store.kind).toBe("redis");
	});
});

describe("redisAccessTokenDenylistModule", () => {
	it("provides accessTokenDenylist off the shared per-purpose client", () => {
		expect(redisAccessTokenDenylistModule.name).toBe("redis-access-token-denylist");
		expect(redisAccessTokenDenylistModule.requires).toContain("accessTokenDenylistClient");
		expect(Object.keys(redisAccessTokenDenylistModule.provides ?? {})).toEqual([
			"accessTokenDenylist",
		]);
	});

	it("is NOT in the replica-unsafe module set — that is the whole point of it", async () => {
		const { REPLICA_UNSAFE_MODULES } = await import("@o3co/auth-provider-core");
		expect(REPLICA_UNSAFE_MODULES).not.toContain(redisAccessTokenDenylistModule.name);
	});
});
