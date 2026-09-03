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

	it("falls back rather than throwing when defaultLimit is null or malformed", async () => {
		// `redisRateLimiterBuilder` accepts a config object that never passed the
		// zod schema, so `defaultLimit` can arrive as null or as a non-object.
		// Dereferencing it would crash the limiter at construction — the one
		// component whose job is to stay up while things go wrong.
		for (const bad of [null, undefined, "nonsense", 42, {}]) {
			const redis = fakeRedis();
			const limiter = createRedisRateLimiter({
				client: redis,
				defaultLimit: bad as never,
			});
			const decision = await limiter.check("anything:foo", { ip: "1.2.3.4" });
			expect(decision.allowed).toBe(true);
			expect(redis.ttls.get("anything:foo")).toBe(60);
		}
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

/**
 * #458 — behind Redis the guard's 429 carried no `Retry-After`, because this
 * adapter reported no `resetAt` while the memory adapter did. The Lua script
 * now hands back the counter key's PTTL with the count, and the limiter turns
 * it into the moment the window ends.
 */
describe("createRedisRateLimiter — resetAt (#458)", () => {
	/**
	 * A client on the two-method contract, whose window started
	 * `windowAgeMs` ago — so the PTTL it reports is the window minus that.
	 */
	const fakeRedisWithPttl = (windowAgeMs: number) => {
		const counts = new Map<string, number>();
		return {
			async incrementWithTtl(key: string, ttlSeconds: number) {
				return (await this.incrementWithTtlAndPttl(key, ttlSeconds)).count;
			},
			async incrementWithTtlAndPttl(key: string, ttlSeconds: number) {
				const next = (counts.get(key) ?? 0) + 1;
				counts.set(key, next);
				return { count: next, pttl: ttlSeconds * 1000 - windowAgeMs };
			},
		};
	};
	const key = "token:ip:1.2.3.4";
	const limits = { token: { limit: 1, windowSeconds: 60 } };

	it("reports resetAt from the counter's remaining TTL, inside the window", async () => {
		const limiter = createRedisRateLimiter({ client: fakeRedisWithPttl(15_000), limits });
		const before = Date.now();
		await limiter.check(key, { ip: "1.2.3.4" });
		const denied = await limiter.check(key, { ip: "1.2.3.4" });
		const after = Date.now();

		expect(denied.allowed).toBe(false);
		// 45 s remain of a 60 s window that started 15 s ago.
		const resetAt = denied.resetAt?.getTime() ?? Number.NaN;
		expect(resetAt).toBeGreaterThanOrEqual(before + 45_000);
		expect(resetAt).toBeLessThanOrEqual(after + 45_000);
	});

	it("carries resetAt on the allow path too, so RateLimit-Reset is emitted", async () => {
		const limiter = createRedisRateLimiter({ client: fakeRedisWithPttl(0), limits });
		const before = Date.now();
		const allowed = await limiter.check(key, { ip: "1.2.3.4" });

		expect(allowed.allowed).toBe(true);
		expect(allowed.resetAt?.getTime() ?? Number.NaN).toBeGreaterThanOrEqual(before + 60_000);
	});

	it("reports no resetAt for a client on the one-method contract", async () => {
		// A custom client written against the original `incrementWithTtl`-only
		// contract keeps working; it just cannot say when the window ends.
		const limiter = createRedisRateLimiter({ client: fakeRedis(), limits });
		await limiter.check(key, { ip: "1.2.3.4" });
		const denied = await limiter.check(key, { ip: "1.2.3.4" });

		expect(denied.allowed).toBe(false);
		expect(denied.resetAt).toBeUndefined();
	});

	it("reports no resetAt when the client hands back a PTTL with no expiry", async () => {
		// -1 (no expiry) / -2 (no key) cannot follow a script that just set the
		// TTL; a client answering them broke the contract, and no reset time is
		// better than a wrong one.
		const limiter = createRedisRateLimiter({
			client: {
				async incrementWithTtl() {
					return 1;
				},
				async incrementWithTtlAndPttl() {
					return { count: 1, pttl: -1 };
				},
			},
			limits,
		});
		const decision = await limiter.check(key, { ip: "1.2.3.4" });

		expect(decision.resetAt).toBeUndefined();
	});
});
