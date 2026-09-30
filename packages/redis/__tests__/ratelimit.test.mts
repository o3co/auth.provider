/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { redisRateLimiterBuilder } from "../src/ratelimit.mjs";

// `createRedisRateLimiter`'s own behaviour lives in ratelimit-atomicity.test.mts,
// which exercises it against the atomic `incrementWithTtl` contract.

describe("redisRateLimiterBuilder", () => {
	it("rejects missing client", () => {
		expect(() => redisRateLimiterBuilder({}, {})).toThrow(/requires config.client/);
	});

	it("constructs limiter when client is provided", () => {
		const fakeRedis = {
			async incrementWithTtl(_key: string, _ttlSeconds: number) {
				return 1;
			},
		};
		const limiter = redisRateLimiterBuilder({ client: fakeRedis }, {});
		expect(limiter.kind).toBe("redis");
	});

	it("declares the defaultLimit it applies, the built-in 60 per 60 s when none is given", () => {
		const client = { incrementWithTtl: async () => 1 };
		expect(redisRateLimiterBuilder({ client }, {}).defaultLimit).toEqual({
			limit: 60,
			windowSeconds: 60,
		});
		expect(
			redisRateLimiterBuilder({ client, defaultLimit: { limit: 7, windowSeconds: 90 } }, {})
				.defaultLimit,
		).toEqual({ limit: 7, windowSeconds: 90 });
	});

	it("answers the outage policy it was configured with", () => {
		const client = { incrementWithTtl: async () => 1 };
		expect(redisRateLimiterBuilder({ client, failMode: "open" }, {}).failMode).toBe("open");
		expect(redisRateLimiterBuilder({ client }, {}).failMode).toBeUndefined();
		expect(() => redisRateLimiterBuilder({ client, failMode: "maybe" }, {})).toThrow(
			/^createRedisRateLimiter: failMode must be "open" or "closed"/,
		);
	});
});
