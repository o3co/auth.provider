/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * #458 — the Redis rate limiter against a real Redis.
 *
 * `ratelimit-atomicity.test.mts` pins the limiter's arithmetic on a fake. This
 * file pins the one thing a fake cannot: that `LUA_INCREMENT_WITH_TTL` really
 * returns the counter key's PTTL, read inside the same script after the
 * increment, and that the limiter turns it into a `resetAt` inside the
 * configured window. Behind Redis the guard's 429 used to carry no
 * `Retry-After` because the adapter reported no reset time at all.
 */

import { Redis } from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisRateLimiter } from "../src/ratelimit.mjs";

let container: StartedTestContainer;
let redis: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	redis = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	await redis?.quit();
	await container?.stop();
});

describe("createRedisRateLimiter on ioredis — resetAt (#458)", () => {
	it("reports a resetAt inside the window, from the counter key's PTTL", async () => {
		const limiter = createRedisRateLimiter({
			client: makeIoredisClients(redis).rateLimiterClient,
			limits: { t458: { limit: 1, windowSeconds: 60 } },
		});
		const key = `t458:ip:${Date.now()}`;

		const before = Date.now();
		const first = await limiter.check(key, {});
		const denied = await limiter.check(key, {});
		const after = Date.now();

		expect(first.allowed).toBe(true);
		expect(denied.allowed).toBe(false);
		for (const decision of [first, denied]) {
			// A fresh key's PTTL is (almost) the whole window: the reset lands
			// about 60 s out, and never past `after + window`.
			const resetAt = decision.resetAt?.getTime() ?? Number.NaN;
			expect(resetAt).toBeGreaterThanOrEqual(before + 59_000);
			expect(resetAt).toBeLessThanOrEqual(after + 60_000);
		}
	});
});
