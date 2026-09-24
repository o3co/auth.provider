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

	it("seeds webauthn-authentication-options from webauthn.rateLimit.authenticationOptions", async () => {
		// The route's budget lives in the WebAuthn section, as login's lives
		// in `rateLimit.login`; unseeded, it ran on the 60 per 60 s default.
		const cfg = {
			memoryRateLimiter: {
				limits: {},
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: 10_000,
			},
			webauthn: { rateLimit: { authenticationOptions: { limit: 2, windowSeconds: 60 } } },
		};
		const limiter = memoryRateLimiterModule.provides?.rateLimiter?.({ config: cfg } as never);
		if (!limiter) throw new Error("rateLimiter provider missing");
		const key = "webauthn-authentication-options:ip:1.2.3.4";
		expect((await limiter.check(key, { ip: "1.2.3.4" })).limit).toBe(2);
		expect((await limiter.check(key, { ip: "1.2.3.4" })).allowed).toBe(true);
		expect((await limiter.check(key, { ip: "1.2.3.4" })).allowed).toBe(false);
	});

	it("refuses a seeded budget that is present but unusable, naming the config key and not the limiter", () => {
		// A configuration someone wrote, never passed through a schema: it
		// used to be skipped, and the prefix ran on the 60 per 60 s default.
		const provide = (extra: Record<string, unknown>) => () =>
			memoryRateLimiterModule.provides?.rateLimiter?.({
				config: {
					memoryRateLimiter: {
						limits: {},
						defaultLimit: { limit: 60, windowSeconds: 60 },
						maxBuckets: 10_000,
					},
					...extra,
				},
			} as never);
		const cases: [Record<string, unknown>, RegExp][] = [
			[{ rateLimit: { login: { windowMs: 900_000, limit: 0 } } }, /rateLimit\.login must be/],
			[
				{ oauth: { deviceAuthorization: { rateLimit: { limit: 5, windowSeconds: 0 } } } },
				/oauth\.deviceAuthorization\.rateLimit must be/,
			],
			[
				{
					webauthn: {
						rateLimit: { authenticationOptions: { limit: "thirty", windowSeconds: 60 } },
					},
				},
				/webauthn\.rateLimit\.authenticationOptions must be/,
			],
		];
		for (const [extra, key] of cases) {
			expect(provide(extra), JSON.stringify(extra)).toThrow(RangeError);
			expect(provide(extra), JSON.stringify(extra)).toThrow(key);
			expect(provide(extra), JSON.stringify(extra)).not.toThrow(/createMemoryRateLimiter/);
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
