/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, expect, it, vi } from "vitest";
import { createRateLimiterFactory, registerBuiltinRateLimiters } from "#/ratelimit/factory.mjs";

describe("createRateLimiterFactory", () => {
	it("creates factory and resolves custom limiter", async () => {
		const factory = createRateLimiterFactory();
		factory.register("stub", () => ({
			kind: "stub",
			async check() {
				return { allowed: true };
			},
		}));
		const limiter = await factory.create({ type: "stub" });
		expect(limiter.kind).toBe("stub");
	});
});

describe("registerBuiltinRateLimiters (memory)", () => {
	it("memory sink respects limit and window", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-04-21T00:00:00Z"));

		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "memory",
			limits: { "login.ip": { limit: 3, windowSeconds: 60 } },
		});

		const key = "login.ip:1.2.3.4";
		const first = await limiter.check(key, { ip: "1.2.3.4" });
		expect(first.allowed).toBe(true);
		expect(first.remaining).toBe(2);

		const second = await limiter.check(key, { ip: "1.2.3.4" });
		const third = await limiter.check(key, { ip: "1.2.3.4" });
		expect(second.allowed).toBe(true);
		expect(third.allowed).toBe(true);
		expect(third.remaining).toBe(0);

		const fourth = await limiter.check(key, { ip: "1.2.3.4" });
		expect(fourth.allowed).toBe(false);
		expect(fourth.reason).toBeDefined();

		vi.advanceTimersByTime(61_000);
		const reset = await limiter.check(key, { ip: "1.2.3.4" });
		expect(reset.allowed).toBe(true);
		expect(reset.remaining).toBe(2);

		vi.useRealTimers();
	});

	it("memory sink falls back to default limit when key prefix missing from config", async () => {
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "memory",
			defaultLimit: { limit: 1, windowSeconds: 60 },
		});
		const first = await limiter.check("unknown:x", {});
		const second = await limiter.check("unknown:x", {});
		expect(first.allowed).toBe(true);
		expect(second.allowed).toBe(false);
	});

	it("memory sink bounds bucket growth by evicting a bucket when full", async () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2026-05-09T00:00:00Z"));

			const factory = createRateLimiterFactory();
			registerBuiltinRateLimiters(factory);
			const limiter = await factory.create({
				type: "memory",
				defaultLimit: { limit: 2, windowSeconds: 60 },
				maxBuckets: 2,
			});

			await limiter.check("unknown:A", {});
			vi.advanceTimersByTime(1);
			await limiter.check("unknown:B", {});
			vi.advanceTimersByTime(1);
			await limiter.check("unknown:C", {});

			const existingB = await limiter.check("unknown:B", {});
			expect(existingB.allowed).toBe(true);
			expect(existingB.remaining).toBe(0);

			const recreatedA = await limiter.check("unknown:A", {});
			expect(recreatedA.allowed).toBe(true);
			expect(recreatedA.remaining).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("eviction makes progress even when bucket resetAt is non-finite (misconfigured windowSeconds)", async () => {
		// Regression: a misconfigured spec with NaN windowSeconds produces
		// NaN resetAt. evictEarliestResetBucket previously used `<` against
		// POSITIVE_INFINITY, and `NaN < x` is false, so when every bucket
		// had NaN resetAt no key was selected and the caller's
		// `while (buckets.size >= maxBuckets)` loop pinned the event loop.
		// This test would hang forever before the fix; vitest's default
		// timeout makes the regression visible as a failure.
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "memory",
			defaultLimit: { limit: 1, windowSeconds: Number.NaN },
			maxBuckets: 2,
		});

		// Fill: both buckets get resetAt = now + NaN*1000 = NaN.
		await limiter.check("nan:A", {});
		await limiter.check("nan:B", {});
		// Trigger eviction: must return rather than spin-loop.
		const result = await limiter.check("nan:C", {});
		expect(result.allowed).toBe(true);
	});
});

describe("memory rate limiter — per-key isolation", () => {
	it("tracks different keys independently", async () => {
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "memory",
			limits: { shared: { limit: 2, windowSeconds: 60 } },
		});
		const a1 = await limiter.check("shared:A", {});
		const a2 = await limiter.check("shared:A", {});
		const a3 = await limiter.check("shared:A", {});
		expect(a1.allowed).toBe(true);
		expect(a2.allowed).toBe(true);
		expect(a3.allowed).toBe(false);

		const b1 = await limiter.check("shared:B", {});
		expect(b1.allowed).toBe(true);
		expect(b1.remaining).toBe(1);
	});
});

describe("memory rate limiter — concurrent burst", () => {
	it("counts parallel requests within the limit", async () => {
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "memory",
			limits: { burst: { limit: 5, windowSeconds: 60 } },
		});
		const results = await Promise.all(
			Array.from({ length: 10 }, () => limiter.check("burst:K", {})),
		);
		const allowed = results.filter((r) => r.allowed).length;
		const denied = results.filter((r) => !r.allowed).length;
		expect(allowed).toBe(5);
		expect(denied).toBe(5);
	});
});

describe("registerBuiltinRateLimiters — Phase 10 redis relocation", () => {
	it("does NOT register the 'redis' backend (relocated to @o3co/auth-provider-redis in Phase 10)", () => {
		const f = createRateLimiterFactory();
		registerBuiltinRateLimiters(f);
		expect(f.registeredTypes()).not.toContain("redis");
	});
});
