/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
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

	it("limits requests per the configured spec", async () => {
		const cfg = {
			memoryRateLimiter: {
				limits: { "test.ip": { limit: 2, windowSeconds: 60 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
			},
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ config: cfg } as never);
		expect(limiter).toBeDefined();
		if (!limiter) return;
		const a = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(a.allowed).toBe(true);
		const b = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(b.allowed).toBe(true);
		const c = await limiter.check("test.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(c.allowed).toBe(false);
	});
});
