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

/**
 * The `RateLimiter` port's optional `failMode` — the limiter's own outage
 * policy — what core's in-process limiter declares, and the test double.
 * The port's contract suite is the test kit's, and runs over the double and
 * the in-process limiter there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createMemoryRateLimiter } from "#/ratelimit/memory.mjs";
import type { RateLimiter, RateLimitFailMode, RateLimitSpec } from "#/ratelimit/types.mjs";
import { createTestRateLimiter } from "#/testing/index.mjs";

describe("RateLimiter.failMode", () => {
	it("is optional, and is the guard's outage vocabulary", () => {
		expectTypeOf<RateLimiter["failMode"]>().toEqualTypeOf<RateLimitFailMode | undefined>();
		const withoutOne: RateLimiter = { kind: "none", check: async () => ({ allowed: true }) };
		const withOne: RateLimiter = {
			kind: "one",
			failMode: "open",
			check: async () => ({ allowed: true }),
		};
		expect(withoutOne.failMode).toBeUndefined();
		expect(withOne.failMode).toBe("open");
	});
});

describe("createMemoryRateLimiter", () => {
	const spec: RateLimitSpec = { limit: 10, windowSeconds: 60 };

	it("declares no outage policy: it has no backend to lose", () => {
		expect(createMemoryRateLimiter({ defaultLimit: spec }).failMode).toBeUndefined();
	});

	it("declares the defaultLimit it was built with, frozen", () => {
		const defaultLimit = { limit: 7, windowSeconds: 90 };
		const declared = createMemoryRateLimiter({ defaultLimit }).defaultLimit;
		defaultLimit.limit = 700;
		expect(declared).toEqual({ limit: 7, windowSeconds: 90 });
		expect(Object.isFrozen(declared)).toBe(true);
	});
});

describe("createTestRateLimiter", () => {
	it("allows every check without a limit, and records each key", async () => {
		const limiter = createTestRateLimiter();
		expect(limiter.kind).toBe("test");
		expect("failMode" in limiter).toBe(false);
		for (let i = 0; i < 5; i++) {
			expect((await limiter.check("login:ip:192.0.2.1", {})).allowed).toBe(true);
		}
		await limiter.check("token:ip:192.0.2.2", {});
		expect(limiter.checked).toEqual([...Array(5).fill("login:ip:192.0.2.1"), "token:ip:192.0.2.2"]);
		expect(Object.isFrozen(limiter.checked)).toBe(true);
	});

	it("refuses a key past its limit, counting each key apart", async () => {
		const limiter = createTestRateLimiter({ limit: 2, failMode: "open" });
		expect(limiter.failMode).toBe("open");
		const answers = [];
		for (let i = 0; i < 3; i++) answers.push(await limiter.check("a", {}));
		expect(answers.map((d) => [d.allowed, d.remaining, d.limit])).toEqual([
			[true, 1, 2],
			[true, 0, 2],
			[false, 0, 2],
		]);
		expect((await limiter.check("b", {})).allowed).toBe(true);
	});

	it("stands in for a backend that is down: every check rejects with the error, until it recovers", async () => {
		const limiter = createTestRateLimiter();
		const outage = new Error("down");
		limiter.failWith(outage);
		await expect(limiter.check("a", {})).rejects.toBe(outage);
		limiter.recover();
		expect((await limiter.check("a", {})).allowed).toBe(true);
	});
});
