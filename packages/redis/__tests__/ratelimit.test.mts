/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { redisRateLimiterBuilder } from "../src/ratelimit.mjs";

// `createRedisRateLimiter`'s own behaviour lives in ratelimit-atomicity.test.mts,
// which exercises it against the atomic `incrementWithTtl` contract (#269).

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
});
