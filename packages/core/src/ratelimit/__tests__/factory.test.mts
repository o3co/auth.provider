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
import { createMemoryRateLimiter } from "#/ratelimit/memory.mjs";

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

describe("memory rate limiter — a window past the Date range", () => {
	// 1e13 s is 1e16 ms: no window that long ends inside ECMAScript's Date
	// range, so its bucket's reset is an Invalid Date, and the Redis adapter
	// cannot set it as a TTL at all. Both adapters refuse it when built, and
	// neither serves a looser default in its place.
	const PAST_THE_DATE_RANGE = [1e13, 1e17];
	const SANE = { limit: 60, windowSeconds: 60 };

	it("refuses a per-prefix spec with such a window when it is built", () => {
		for (const windowSeconds of PAST_THE_DATE_RANGE) {
			expect(
				() =>
					createMemoryRateLimiter({
						limits: { big: { limit: 5, windowSeconds } },
						defaultLimit: SANE,
					}),
				String(windowSeconds),
			).toThrow(RangeError);
		}
	});

	it("refuses a default with such a window when it is built", () => {
		for (const windowSeconds of PAST_THE_DATE_RANGE) {
			expect(
				() => createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 5, windowSeconds } }),
				String(windowSeconds),
			).toThrow(RangeError);
		}
	});

	it("refuses it through the factory as well, rather than dropping the spec", async () => {
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		await expect(
			(async () =>
				factory.create({ type: "memory", limits: { big: { limit: 5, windowSeconds: 1e13 } } }))(),
		).rejects.toThrow(RangeError);
	});
});

describe("memory rate limiter — a spec it cannot apply as written", () => {
	// The Redis adapter refuses the same set, by the same predicate: one
	// configuration, one budget, whichever adapter is mounted.
	const UNUSABLE = [0, Number.NaN, 1.5, -1];
	const SANE = { limit: 60, windowSeconds: 60 };
	const specs = UNUSABLE.flatMap((bad) => [
		{ limit: 5, windowSeconds: bad },
		{ limit: bad, windowSeconds: 60 },
	]);
	const label = (spec: { limit: number; windowSeconds: number }) =>
		`${String(spec.limit)} per ${String(spec.windowSeconds)} s`;

	it("refuses a zero, NaN, fractional or negative window or limit when it is built", () => {
		for (const spec of specs) {
			expect(
				() => createMemoryRateLimiter({ limits: { big: spec }, defaultLimit: SANE }),
				`limits: ${label(spec)}`,
			).toThrow(RangeError);
			expect(
				() => createMemoryRateLimiter({ limits: {}, defaultLimit: spec }),
				`defaultLimit: ${label(spec)}`,
			).toThrow(RangeError);
		}
	});

	it("refuses them through the factory too, which used to drop a spec or put its own default in", async () => {
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		for (const spec of [...specs, { limit: "5", windowSeconds: "60" }]) {
			await expect(
				(async () => factory.create({ type: "memory", limits: { big: spec } }))(),
				`limits: ${JSON.stringify(spec)}`,
			).rejects.toThrow(RangeError);
		}
		for (const bad of [null, "nonsense", 42, {}, { limit: 5, windowSeconds: Number.NaN }]) {
			await expect(
				(async () => factory.create({ type: "memory", defaultLimit: bad }))(),
				`defaultLimit: ${String(bad)}`,
			).rejects.toThrow(RangeError);
		}
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

	it("never holds a bucket with a non-finite reset: a NaN window is refused when it is built", async () => {
		// Regression: a misconfigured spec with NaN windowSeconds produced NaN
		// resetAt, and evictEarliestResetBucket, comparing with `<`, selected
		// no key when every bucket had one — the caller's
		// `while (buckets.size >= maxBuckets)` loop pinned the event loop. The
		// eviction still makes progress on such a bucket, but none can exist
		// now: the spec is refused before the limiter holds anything.
		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		await expect(
			(async () =>
				factory.create({
					type: "memory",
					defaultLimit: { limit: 1, windowSeconds: Number.NaN },
					maxBuckets: 2,
				}))(),
		).rejects.toThrow(RangeError);
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
