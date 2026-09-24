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

	it("seeds webauthn-authentication-options from webauthn.rateLimit.authenticationOptions", async () => {
		// The route's budget lives in the WebAuthn section; unseeded, the
		// unauthenticated options route ran on this adapter's 60 per 60 s.
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
			webauthn: { rateLimit: { authenticationOptions: { limit: 2, windowSeconds: 60 } } },
		};
		const limiter = redisRateLimiterModule.provides?.rateLimiter?.({
			config,
			rateLimiterClient: client,
		} as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		const key = "webauthn-authentication-options:ip:1.2.3.4";
		const first = await limiter.check(key, { ip: "1.2.3.4" });
		expect(first.limit).toBe(2);
		expect((await limiter.check(key, { ip: "1.2.3.4" })).allowed).toBe(true);
		expect((await limiter.check(key, { ip: "1.2.3.4" })).allowed).toBe(false);
	});

	it("refuses a seeded budget that is present but unusable, naming the config key and not the limiter", () => {
		const provide = (extra: Record<string, unknown>) => () =>
			redisRateLimiterModule.provides?.rateLimiter?.({
				config: {
					redisRateLimiter: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 } },
					...extra,
				},
				rateLimiterClient: { incrementWithTtl: async () => 1 },
			} as never);
		const cases: [Record<string, unknown>, RegExp][] = [
			[{ rateLimit: { login: { windowMs: 1e19, limit: 20 } } }, /rateLimit\.login must be/],
			[
				{ oauth: { deviceAuthorization: { rateLimit: { limit: 5, windowSeconds: 1e13 } } } },
				/oauth\.deviceAuthorization\.rateLimit must be/,
			],
			[
				{ webauthn: { rateLimit: { authenticationOptions: { limit: 0, windowSeconds: 60 } } } },
				/webauthn\.rateLimit\.authenticationOptions must be/,
			],
		];
		for (const [extra, key] of cases) {
			expect(provide(extra), JSON.stringify(extra)).toThrow(key);
			expect(provide(extra), JSON.stringify(extra)).not.toThrow(/createRedisRateLimiter/);
		}
	});

	it("refuses a window longer than a year in its own schema", () => {
		const schema = redisRateLimiterModule.configSchema;
		for (const redisRateLimiter of [
			{ defaultLimit: { limit: 5, windowSeconds: 31_536_001 } },
			{ limits: { token: { limit: 5, windowSeconds: 1e13 } } },
		]) {
			expect(
				schema?.safeParse({ redisRateLimiter })?.success,
				JSON.stringify(redisRateLimiter),
			).toBe(false);
		}
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
