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

	it("requires config and the contributed budgets", () => {
		expect(memoryRateLimiterModule.requires).toEqual(["config", "rateLimitBudgetResolver"]);
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

	it("refuses a window longer than a year in its own schema", () => {
		for (const memoryRateLimiter of [
			{ defaultLimit: { limit: 5, windowSeconds: 31_536_001 } },
			{ limits: { token: { limit: 5, windowSeconds: 1e13 } } },
		]) {
			expect(
				memoryRateLimiterModule.configSchema?.safeParse({ memoryRateLimiter })?.success,
				JSON.stringify(memoryRateLimiter),
			).toBe(false);
		}
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

	it("limits a prefix by the budget its owner contributed, read at each check, under its own limits entry", async () => {
		const budgets = new Map<string, { limit: number; windowSeconds: number }>();
		const cfg = {
			memoryRateLimiter: {
				limits: { login: { limit: 4, windowSeconds: 45 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 10_000,
			},
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({
			config: cfg,
			rateLimitBudgetResolver: {
				get: (prefix: string) => budgets.get(prefix),
				entries: () => budgets.entries(),
			},
		} as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		budgets.set("mfa", { limit: 2, windowSeconds: 300 });
		budgets.set("login", { limit: 20, windowSeconds: 900 });

		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(2);
		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).allowed).toBe(true);
		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).allowed).toBe(false);
		expect((await limiter.check("login:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(4);
		expect((await limiter.check("token:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(60);
	});

	it("reads no owner's key: a prefix nothing contributes a budget for falls to its defaultLimit", async () => {
		// The owners' keys are their modules' to read, and to refuse; the
		// limiter reads their budgets through rateLimitBudgetResolver alone.
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({
			config: {
				memoryRateLimiter: {
					limits: {},
					defaultLimit: { limit: 60, windowSeconds: 60 },
					maxBuckets: 10_000,
				},
				rateLimit: { login: { windowMs: 900_000, limit: 0 } },
				"device-grant": { rateLimit: { limit: 2, windowSeconds: 300 } },
				webauthn: { rateLimit: { authenticationOptions: { limit: "thirty", windowSeconds: 60 } } },
				mfa: {
					rateLimit: { routes: { limit: 2, windowSeconds: 300 } },
					factors: { email: { sendLimit: { limit: 1, windowSeconds: 3600 } } },
				},
			},
			rateLimitBudgetResolver: { get: () => undefined, entries: () => new Map().entries() },
		} as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		for (const key of [
			"login:ip:1.2.3.4",
			"device_verification:user:u1",
			"webauthn-authentication-options:ip:1.2.3.4",
			"mfa:ip:1.2.3.4",
			"mfa-email:user:u1",
		]) {
			expect((await limiter.check(key, { ip: "1.2.3.4" })).limit, key).toBe(60);
		}
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
