/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type { RateLimiter } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { redisRateLimiterModule } from "../src/ratelimit.mjs";

describe("redisRateLimiterModule", () => {
	it("has the canonical name", () => {
		expect(redisRateLimiterModule.name).toBe("redis-rate-limiter");
	});

	it("requires rateLimiterClient and the contributed budgets", () => {
		expect(redisRateLimiterModule.requires).toEqual([
			"rateLimiterClient",
			"rateLimitBudgetResolver",
		]);
	});

	it("limits a prefix by the budget its owner contributed, read at each check, under its own limits entry", async () => {
		const counts = new Map<string, number>();
		const windows: number[] = [];
		const client = {
			async incrementWithTtl(key: string, ttlSeconds: number) {
				windows.push(ttlSeconds);
				const next = (counts.get(key) ?? 0) + 1;
				counts.set(key, next);
				return next;
			},
		};
		const budgets = new Map<string, { limit: number; windowSeconds: number }>();
		const limiter = redisRateLimiterModule.provides?.rateLimiter?.({
			section: {
				limits: { login: { limit: 4, windowSeconds: 45 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
				failMode: "closed",
			},
			rateLimiterClient: client,
			rateLimitBudgetResolver: {
				get: (prefix: string) => budgets.get(prefix),
				entries: () => budgets.entries(),
			},
		} as never) as RateLimiter | undefined;
		if (!limiter) throw new Error("rateLimiter provider missing");
		budgets.set("mfa", { limit: 2, windowSeconds: 300 });
		budgets.set("login", { limit: 20, windowSeconds: 900 });

		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(2);
		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).allowed).toBe(true);
		expect((await limiter.check("mfa:ip:1.2.3.4", { ip: "1.2.3.4" })).allowed).toBe(false);
		expect((await limiter.check("login:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(4);
		expect((await limiter.check("token:ip:1.2.3.4", { ip: "1.2.3.4" })).limit).toBe(60);
		expect(windows).toEqual([300, 300, 300, 45, 60]);
	});

	it("provides rateLimiter", () => {
		expect(typeof redisRateLimiterModule.provides?.rateLimiter).toBe("function");
	});

	it("reads no owner's key: a prefix nothing contributes a budget for falls to its defaultLimit", async () => {
		// The owners' keys are their modules' to read, and to refuse; the
		// limiter reads their budgets through rateLimitBudgetResolver alone.
		const limiter = redisRateLimiterModule.provides?.rateLimiter?.({
			section: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 }, failMode: "closed" },
			config: {
				rateLimit: { login: { windowMs: 900_000, limit: 0 } },
				"device-grant": { rateLimit: { limit: 2, windowSeconds: 300 } },
				webauthn: { rateLimit: { authenticationOptions: { limit: "thirty", windowSeconds: 60 } } },
				mfa: {
					rateLimit: { routes: { limit: 2, windowSeconds: 300 } },
					factors: { email: { sendLimit: { limit: 1, windowSeconds: 3600 } } },
				},
			},
			rateLimiterClient: { incrementWithTtl: async () => 1 },
			rateLimitBudgetResolver: { get: () => undefined, entries: () => new Map().entries() },
		} as never) as RateLimiter | undefined;
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

	describe("its outage policy", () => {
		const provided = (failMode: "open" | "closed") =>
			redisRateLimiterModule.provides?.rateLimiter?.({
				section: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 }, failMode },
				rateLimiterClient: { incrementWithTtl: async () => 1 },
				rateLimitBudgetResolver: { get: () => undefined, entries: () => new Map().entries() },
			} as never) as RateLimiter | undefined;

		it.each(["open", "closed"] as const)(
			"answers redis-rate-limiter.failMode = %s as the limiter's own",
			(failMode) => {
				expect(provided(failMode)?.failMode).toBe(failMode);
			},
		);

		it("is closed when the section gives none", () => {
			expect(redisRateLimiterModule.section?.schema.parse({})).toMatchObject({
				failMode: "closed",
			});
		});

		it("refuses a failMode that is neither open nor closed, naming the key", () => {
			for (const failMode of ["maybe", "", "OPEN", 1, null]) {
				const parsed = redisRateLimiterModule.section?.schema.safeParse({ failMode });
				expect(parsed?.success, JSON.stringify(failMode)).toBe(false);
				expect(parsed?.error?.issues.map((issue) => issue.path.join("."))).toEqual(["failMode"]);
			}
		});
	});

	it("refuses a window longer than a year, and a key it does not declare, in its section's schema", () => {
		const schema = redisRateLimiterModule.section?.schema;
		for (const section of [
			{ defaultLimit: { limit: 5, windowSeconds: 31_536_001 } },
			{ limits: { token: { limit: 5, windowSeconds: 1e13 } } },
			{ failmode: "open" },
		]) {
			expect(schema?.safeParse(section)?.success, JSON.stringify(section)).toBe(false);
		}
	});

	it("reads its own section, redis-rate-limiter, its defaultLimit 60 per 60 s unless written", () => {
		expect(redisRateLimiterModule.configSchema).toBeUndefined();
		expect(redisRateLimiterModule.section?.schema.parse(undefined)).toEqual({
			limits: {},
			defaultLimit: { limit: 60, windowSeconds: 60 },
			failMode: "closed",
		});
		expect(
			redisRateLimiterModule.section?.schema.parse({
				defaultLimit: { limit: "5", windowSeconds: "30" },
			}),
		).toMatchObject({ defaultLimit: { limit: 5, windowSeconds: 30 } });
	});
});
