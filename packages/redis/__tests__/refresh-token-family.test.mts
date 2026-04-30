/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll } from "vitest";
import { createRedisRefreshTokenFamilyStore } from "../src/refresh-token-family.mjs";
import type { DisposableRedisClient, RedisClient, RedisMulti } from "../src/types.mjs";
import { runRedisClientDuplicateContract } from "./adapters.redis-client.contract.mjs";
import { runRefreshTokenFamilyStoreContract } from "./adapters.refresh-token-family.contract.mjs";

let container: StartedTestContainer;
let client: Redis;
let keyCounter = 0;

/**
 * Adapt a raw ioredis Redis instance to the structural RedisClient + provide
 * `duplicate()` returning a DisposableRedisClient (Symbol.asyncDispose calls
 * the duplicated ioredis instance's quit()). The base client itself is NOT
 * disposable — only duplicates owned by `updateFamily` need lifetime
 * management.
 */
const adapt = (raw: Redis): RedisClient => ({
	set: (key, value, mode, ttlMs, condition) => raw.set(key, value, mode, ttlMs, condition),
	del: (key) => raw.del(key),
	pttl: (key) => raw.pttl(key),
	exists: (key) => raw.exists(key),
	get: (key) => raw.get(key),
	watch: (...keys) => raw.watch(...keys),
	unwatch: () => raw.unwatch(),
	multi: () => {
		const m = raw.multi();
		const facade: RedisMulti = {
			set: (key, value, mode, ttlMs) => {
				m.set(key, value, mode, ttlMs);
				return facade;
			},
			exec: async () => {
				const result = await m.exec();
				return result;
			},
		};
		return facade;
	},
	duplicate: (): DisposableRedisClient => {
		const dup = raw.duplicate();
		const wrapped = adapt(dup);
		return Object.assign(wrapped, {
			[Symbol.asyncDispose]: async () => {
				await dup.quit();
			},
		});
	},
});

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 30_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

runRefreshTokenFamilyStoreContract(async () => {
	keyCounter++;
	return createRedisRefreshTokenFamilyStore({
		client: adapt(client),
		keyPrefix: `rtfam:test-${keyCounter}:`,
		casRetryLimit: 50, // generous limit for the concurrency property test
	});
});

// T4 hardening (Claude review I1): RedisClient.duplicate() NORMATIVE contract
// suite. The `adapt()` wrapper above is the canonical in-tree implementation;
// running the contract against it ensures any future refactor of `adapt()`
// (or any consumer's wrapper) preserves the WATCH-isolation guarantee that
// A3 updateFamily depends on.
runRedisClientDuplicateContract(() => adapt(client), `rtfam-contract-${++keyCounter}:`);
