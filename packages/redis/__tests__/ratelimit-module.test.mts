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

	it("requires rateLimiterClient and config", () => {
		expect(redisRateLimiterModule.requires).toEqual(["rateLimiterClient", "config"]);
	});

	it("provides rateLimiter", () => {
		expect(typeof redisRateLimiterModule.provides?.rateLimiter).toBe("function");
	});

	it("seeds device_verification from oauth.deviceAuthorization.rateLimit", async () => {
		// The same seed the memory adapter applies, so the documented budget
		// holds whichever adapter a deployment picks.
		const counts = new Map<string, number>();
		const client = {
			async incrementWithTtl(key: string, _ttlSeconds: number) {
				const next = (counts.get(key) ?? 0) + 1;
				counts.set(key, next);
				return next;
			},
		};
		const config = {
			redisRateLimiter: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 } },
			oauth: { deviceAuthorization: { rateLimit: { limit: 2, windowSeconds: 300 } } },
		};
		const limiter = redisRateLimiterModule.provides?.rateLimiter?.({
			config,
			rateLimiterClient: client,
		} as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		const key = "device_verification:user:u1";
		const first = await limiter.check(key, { userId: "u1" });
		expect(first.allowed).toBe(true);
		expect(first.limit).toBe(2);
		expect((await limiter.check(key, { userId: "u1" })).allowed).toBe(true);
		expect((await limiter.check(key, { userId: "u1" })).allowed).toBe(false);
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
