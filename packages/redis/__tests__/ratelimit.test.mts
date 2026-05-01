/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import { createRedisRateLimiter, redisRateLimiterBuilder } from "../src/ratelimit.mjs";

describe("createRedisRateLimiter", () => {
	it("increments and expires via injected redis commands", async () => {
		const store = new Map<string, number>();
		const ttls = new Map<string, number>();
		const fakeRedis = {
			async incr(key: string) {
				const next = (store.get(key) ?? 0) + 1;
				store.set(key, next);
				return next;
			},
			async expire(key: string, seconds: number) {
				ttls.set(key, seconds);
				return 1;
			},
		};

		const limiter = createRedisRateLimiter({
			client: fakeRedis,
			limits: { "login.ip": { limit: 2, windowSeconds: 60 } },
		});

		const key = "login.ip:1.2.3.4";
		const first = await limiter.check(key, { ip: "1.2.3.4" });
		expect(first.allowed).toBe(true);
		expect(first.remaining).toBe(1);
		expect(ttls.get(key)).toBe(60);

		const second = await limiter.check(key, { ip: "1.2.3.4" });
		expect(second.allowed).toBe(true);
		expect(second.remaining).toBe(0);

		const third = await limiter.check(key, { ip: "1.2.3.4" });
		expect(third.allowed).toBe(false);
	});

	it("uses defaultLimit when no specific limit configured", async () => {
		const store = new Map<string, number>();
		const fakeRedis = {
			async incr(key: string) {
				const next = (store.get(key) ?? 0) + 1;
				store.set(key, next);
				return next;
			},
			async expire(_key: string, _seconds: number) {
				return 1;
			},
		};

		const limiter = createRedisRateLimiter({
			client: fakeRedis,
			defaultLimit: { limit: 1, windowSeconds: 60 },
		});

		const a = await limiter.check("anything:foo", { ip: "1.2.3.4" });
		expect(a.allowed).toBe(true);
		const b = await limiter.check("anything:foo", { ip: "1.2.3.4" });
		expect(b.allowed).toBe(false);
	});
});

describe("redisRateLimiterBuilder", () => {
	it("rejects missing client", () => {
		expect(() => redisRateLimiterBuilder({}, {})).toThrow(/requires config.client/);
	});

	it("constructs limiter when client is provided", () => {
		const fakeRedis = {
			async incr(_key: string) {
				return 1;
			},
			async expire(_key: string, _s: number) {
				return 1;
			},
		};
		const limiter = redisRateLimiterBuilder({ client: fakeRedis }, {});
		expect(limiter.kind).toBe("redis");
	});
});
