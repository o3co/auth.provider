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

import { createMemoryRateLimiter } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisRateLimiter } from "../src/ratelimit.mjs";
import { testRedis } from "./support/redis.mjs";

let redis: Redis;

beforeAll(async () => {
	const at = await testRedis();
	redis = new Redis(at);
});

afterAll(async () => {
	await redis?.quit();
});

describe("createRedisRateLimiter on ioredis — a window no key can carry", () => {
	// 1e13 s is 1e16 ms, past the Date range from any today; 1e17 s is a window
	// the script's EXPIRE refuses after its INCR has run — the #269 shape, a
	// counter with no TTL and a client 429'd for ever.
	const PAST_THE_DATE_RANGE = [1e13, 1e17];

	it("is refused when the limiter is built, and never replaced by a looser default", async () => {
		// Dropping the spec let the default (60 per 60 s) apply where the
		// operator wrote 5: a budget silently twelve times looser — and on the
		// device verification route, the budget RFC 8628 §5.1 sizes the user
		// code against. Refused, it fails the composition instead.
		const client = makeIoredisClients(redis).rateLimiterClient;
		for (const windowSeconds of PAST_THE_DATE_RANGE) {
			expect(
				() => createRedisRateLimiter({ client, limits: { tbig: { limit: 5, windowSeconds } } }),
				String(windowSeconds),
			).toThrow(RangeError);
			expect(
				() => createRedisRateLimiter({ client, defaultLimit: { limit: 5, windowSeconds } }),
				String(windowSeconds),
			).toThrow(RangeError);
		}
		expect(await redis.keys("tbig:*")).toEqual([]);
	});

	it("is refused by the in-process limiter too, so the two adapters give one answer", () => {
		for (const windowSeconds of PAST_THE_DATE_RANGE) {
			expect(
				() =>
					createMemoryRateLimiter({
						limits: { tbig: { limit: 5, windowSeconds } },
						defaultLimit: { limit: 60, windowSeconds: 60 },
					}),
				String(windowSeconds),
			).toThrow(RangeError);
		}
	});
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
