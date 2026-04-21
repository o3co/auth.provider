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

import { describe, expect, it } from "vitest";
import { createRateLimiterFactory, registerBuiltinRateLimiters } from "#/ratelimit/factory.mjs";

describe("registerBuiltinRateLimiters (redis, injected client)", () => {
	it("increments and expires via injected redis commands", async () => {
		// Minimal fake redis client satisfying the two commands the adapter uses.
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

		const factory = createRateLimiterFactory();
		registerBuiltinRateLimiters(factory);
		const limiter = await factory.create({
			type: "redis",
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
});
