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
});
