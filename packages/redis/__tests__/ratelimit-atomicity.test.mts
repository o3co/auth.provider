/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Issue #269 — the limiter ran `INCR` then a separate `EXPIRE`, and only when
 * the count came back as 1. A process death or an `EXPIRE` error in between
 * left the key with no TTL, and because the *check* still succeeded the
 * `failMode` policy never engaged: that key's client was 429'd forever.
 *
 * These tests describe the contract that removes the gap — one atomic
 * operation that increments, establishes or repairs the TTL, and returns the
 * count — and the repair path that unsticks a key already in that state.
 */

import { describe, expect, it } from "vitest";
import { createRedisRateLimiter } from "../src/ratelimit.mjs";

/**
 * A Redis stand-in whose TTL bookkeeping is visible, so a test can assert that
 * no reachable sequence leaves a counter without one.
 */
const fakeRedis = () => {
	const counts = new Map<string, number>();
	const ttls = new Map<string, number>();
	return {
		counts,
		ttls,
		calls: 0,
		async incrementWithTtl(key: string, ttlSeconds: number) {
			this.calls += 1;
			const next = (counts.get(key) ?? 0) + 1;
			counts.set(key, next);
			// The Lua script's semantics: establish the TTL when the key has
			// none, leave an existing one alone (never extend the window).
			if (!ttls.has(key)) ttls.set(key, ttlSeconds);
			return next;
		},
	};
};

describe("createRedisRateLimiter — atomicity (#269)", () => {
	it("counts and limits across a window", async () => {
		const redis = fakeRedis();
		const limiter = createRedisRateLimiter({
			client: redis,
			limits: { "login.ip": { limit: 2, windowSeconds: 60 } },
		});
		const key = "login.ip:1.2.3.4";

		const first = await limiter.check(key, { ip: "1.2.3.4" });
		expect(first).toMatchObject({ allowed: true, remaining: 1 });
		expect(redis.ttls.get(key)).toBe(60);

		expect(await limiter.check(key, { ip: "1.2.3.4" })).toMatchObject({
			allowed: true,
			remaining: 0,
		});
		expect((await limiter.check(key, { ip: "1.2.3.4" })).allowed).toBe(false);
	});

	it("establishes the TTL in the same operation as the increment", async () => {
		// The whole point: there is no window between "counted" and "expires",
		// so no crash or transport error can land in it.
		const redis = fakeRedis();
		const limiter = createRedisRateLimiter({
			client: redis,
			defaultLimit: { limit: 5, windowSeconds: 30 },
		});
		await limiter.check("anything:foo", { ip: "1.2.3.4" });
		expect(redis.calls).toBe(1);
		expect(redis.ttls.get("anything:foo")).toBe(30);
	});

	it("passes the window from the matched limit, not the default", async () => {
		const redis = fakeRedis();
		const limiter = createRedisRateLimiter({
			client: redis,
			limits: { "login.ip": { limit: 2, windowSeconds: 900 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});
		await limiter.check("login.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(redis.ttls.get("login.ip:1.2.3.4")).toBe(900);
	});

	it("uses defaultLimit when a limit spec has a non-positive window", async () => {
		// `EXPIRE key 0` deletes the key, so a zero window would make the
		// limiter count to one forever and never limit anything. The builder
		// path does not go through the zod schema, so the guard lives here.
		const redis = fakeRedis();
		const limiter = createRedisRateLimiter({
			client: redis,
			limits: { "login.ip": { limit: 2, windowSeconds: 0 } },
			defaultLimit: { limit: 1, windowSeconds: 60 },
		});
		await limiter.check("login.ip:1.2.3.4", { ip: "1.2.3.4" });
		expect(redis.ttls.get("login.ip:1.2.3.4")).toBe(60);
		expect((await limiter.check("login.ip:1.2.3.4", { ip: "1.2.3.4" })).allowed).toBe(false);
	});

	it("uses defaultLimit when a limit spec has a non-positive limit", async () => {
		const redis = fakeRedis();
		const limiter = createRedisRateLimiter({
			client: redis,
			limits: { "login.ip": { limit: 0, windowSeconds: 60 } },
			defaultLimit: { limit: 3, windowSeconds: 60 },
		});
		expect((await limiter.check("login.ip:1.2.3.4", { ip: "1.2.3.4" })).remaining).toBe(2);
	});
});
