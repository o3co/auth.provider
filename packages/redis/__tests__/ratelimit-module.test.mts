/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { redisRateLimiterModule } from "../src/ratelimit.mjs";

describe("redisRateLimiterModule", () => {
	it("has the canonical name", () => {
		expect(redisRateLimiterModule.name).toBe("redis-rate-limiter");
	});

	it("requires redisClient and config", () => {
		expect(redisRateLimiterModule.requires).toEqual(["redisClient", "config"]);
	});

	it("provides rateLimiter", () => {
		expect(typeof redisRateLimiterModule.provides?.rateLimiter).toBe("function");
	});

	it("declares a configSchema with redisRateLimiter namespaced key", () => {
		const schema = redisRateLimiterModule.configSchema;
		expect(schema).toBeDefined();
		const parsed = schema?.safeParse({ redisRateLimiter: {} });
		expect(parsed?.success).toBe(true);
		if (parsed?.success) {
			expect(parsed.data.redisRateLimiter.defaultLimit).toEqual({
				limit: 60,
				windowSeconds: 60,
			});
		}
	});
});
