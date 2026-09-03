/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it, vi } from "vitest";
import { memoryRateLimiterModule } from "../module.mjs";

describe("memoryRateLimiterModule", () => {
	it("has the canonical name", () => {
		expect(memoryRateLimiterModule.name).toBe("core-rate-limiter-memory");
	});

	it("requires config only", () => {
		expect(memoryRateLimiterModule.requires).toEqual(["config"]);
	});

	it("provides rateLimiter", () => {
		expect(typeof memoryRateLimiterModule.provides?.rateLimiter).toBe("function");
	});

	it("defaults maxBuckets in module config schema", () => {
		const parsed = memoryRateLimiterModule.configSchema?.parse({});
		expect(parsed).toMatchObject({
			memoryRateLimiter: {
				maxBuckets: 10_000,
			},
		});
	});

	it("limits requests per the configured spec", async () => {
		const cfg = {
			memoryRateLimiter: {
				limits: { "test.ip": { limit: 2, windowSeconds: 60 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 10_000,
			},
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ config: cfg } as never);
		expect(limiter).toBeDefined();
		if (!limiter) throw new Error("rateLimiter provider missing");
		const a = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(a.allowed).toBe(true);
		const b = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(b.allowed).toBe(true);
		const c = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(c.allowed).toBe(false);
	});

	it("seeds device_verification from oauth.deviceAuthorization.rateLimit", async () => {
		// Without the seed a `device_verification:` key falls through to the
		// 60/60s default — twelve times the budget RFC 8628 §5.1's entropy
		// argument (and the boot refusal that cites it) assumes.
		const cfg = {
			memoryRateLimiter: {
				limits: {},
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 10_000,
			},
			oauth: { deviceAuthorization: { rateLimit: { limit: 2, windowSeconds: 300 } } },
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ config: cfg } as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		const key = "device_verification:user:u1";
		const first = await limiter.check(key, { userId: "u1" });
		expect(first.allowed).toBe(true);
		expect(first.limit).toBe(2);
		expect((await limiter.check(key, { userId: "u1" })).allowed).toBe(true);
		expect((await limiter.check(key, { userId: "u1" })).allowed).toBe(false);
	});

	it("bounds bucket growth with memoryRateLimiter.maxBuckets", async () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2026-05-09T00:00:00Z"));

			const cfg = {
				memoryRateLimiter: {
					limits: {},
					defaultLimit: { limit: 2, windowSeconds: 60 },
					maxBuckets: 2,
				},
			};
			const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ config: cfg } as never);
			expect(limiter).toBeDefined();
			if (!limiter) throw new Error("rateLimiter provider missing");

			await limiter.check("test:A", {});
			vi.advanceTimersByTime(1);
			await limiter.check("test:B", {});
			vi.advanceTimersByTime(1);
			await limiter.check("test:C", {});

			const existingB = await limiter.check("test:B", {});
			expect(existingB.remaining).toBe(0);

			const recreatedA = await limiter.check("test:A", {});
			expect(recreatedA.remaining).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});
});
