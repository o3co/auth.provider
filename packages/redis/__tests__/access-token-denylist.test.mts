/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed AccessTokenDenylist (#277).
 *
 * The bundled memory denylist forks per replica, which makes it useless for the
 * thing a denylist is for: a revocation performed on one replica has to be
 * visible on the others. `deployment.mode = "multi"` already refuses it (see
 * core's replica-safety guard), which left multi-replica deployments with no
 * denylist at all — and therefore, before #277, with a `/oauth/revoke` that
 * answered 200 and did nothing.
 */
import type { AccessTokenDenylist } from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createRedisAccessTokenDenylist,
	redisAccessTokenDenylistBuilder,
	redisAccessTokenDenylistModule,
} from "../src/access-token-denylist.mjs";
import type { AccessTokenDenylistClient } from "../src/clients.mjs";

let container: StartedTestContainer;
let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 90_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

function freshStore(): AccessTokenDenylist {
	keyCounter += 1;
	return createRedisAccessTokenDenylist({
		client: client as unknown as AccessTokenDenylistClient,
		keyPrefix: `atdeny:test-${keyCounter}:`,
	});
}

describe("createRedisAccessTokenDenylist", () => {
	it('declares kind "redis"', () => {
		expect(freshStore().kind).toBe("redis");
	});

	it("has() is false for a jti nobody revoked", async () => {
		expect(await freshStore().has("never-added")).toBe(false);
	});

	it("has() is true after add()", async () => {
		const store = freshStore();
		await store.add("j1", Date.now() + 60_000);
		expect(await store.has("j1")).toBe(true);
	});

	it("stops answering true once the token's own exp passes", async () => {
		// The entry's TTL is the access token's remaining lifetime: past that the
		// token fails verification on its `exp` anyway, so keeping the jti would
		// only grow the keyspace forever.
		const store = freshStore();
		await store.add("j2", Date.now() + 150);
		expect(await store.has("j2")).toBe(true);
		await new Promise((r) => setTimeout(r, 250));
		expect(await store.has("j2")).toBe(false);
	});

	it("last add() wins on the expiry", async () => {
		const store = freshStore();
		await store.add("j3", Date.now() + 100);
		await store.add("j3", Date.now() + 5_000);
		await new Promise((r) => setTimeout(r, 250));
		expect(await store.has("j3")).toBe(true);
	});

	it("accepts an already-expired token without writing anything", async () => {
		// RFC 7009 revocation of an expired AT is legal and idempotent, and the
		// route deliberately allows it (`ignoreExpiration: true`). `SET ... PX 0`
		// is a Redis error, so the write is skipped rather than attempted.
		const store = freshStore();
		await expect(store.add("j-expired", Date.now() - 1_000)).resolves.toBeUndefined();
		expect(await store.has("j-expired")).toBe(false);
	});

	it("namespaces keys by keyPrefix so two deployments do not share revocations", async () => {
		const a = createRedisAccessTokenDenylist({
			client: client as unknown as AccessTokenDenylistClient,
			keyPrefix: "atdeny:tenant-a:",
		});
		const b = createRedisAccessTokenDenylist({
			client: client as unknown as AccessTokenDenylistClient,
			keyPrefix: "atdeny:tenant-b:",
		});
		await a.add("shared-jti", Date.now() + 60_000);
		expect(await a.has("shared-jti")).toBe(true);
		expect(await b.has("shared-jti")).toBe(false);
	});
});

describe("redisAccessTokenDenylistBuilder", () => {
	it("refuses to build without a client instead of failing on first revocation", () => {
		expect(() => redisAccessTokenDenylistBuilder({ type: "redis" }, {})).toThrow(/client/);
	});

	it("builds when given a client", () => {
		const store = redisAccessTokenDenylistBuilder(
			{ type: "redis", client: client as unknown as AccessTokenDenylistClient },
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
