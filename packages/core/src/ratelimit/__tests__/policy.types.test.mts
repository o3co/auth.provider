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
 * The outage policy's types: the options a guard or a policy is built from
 * carry no `failMode`, and a `RateLimitPolicy` is only what
 * `createRateLimitPolicy` builds. Compile-time facts: they fire under
 * vitest's typecheck mode only, so this file is in both typecheck lists
 * (vitest.config.mts and tsconfig.test.json).
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { consoleLogger } from "#/logging/consoleLogger.mjs";
import {
	createRateLimitPolicy,
	type RateLimitGuardOptions,
	type RateLimitPolicy,
	type RateLimitPolicyOptions,
} from "#/ratelimit/guard.mjs";
import type { RateLimiter } from "#/ratelimit/types.mjs";

const limiter: RateLimiter = { kind: "types", check: async () => ({ allowed: true }) };

describe("the outage policy's types", () => {
	it("builds a guard or a policy from options that carry no failMode", () => {
		expectTypeOf<RateLimitGuardOptions>().not.toHaveProperty("failMode");
		expectTypeOf<RateLimitPolicyOptions>().not.toHaveProperty("failMode");
	});

	it("types what createRateLimitPolicy builds as a RateLimitPolicy", () => {
		const policy = createRateLimitPolicy({ limiter, tag: "types" });
		expectTypeOf(policy).toEqualTypeOf<RateLimitPolicy>();
		expect(policy.failMode).toBe("closed");
	});

	it("does not accept a structurally built object as a RateLimitPolicy", () => {
		// @ts-expect-error a policy only createRateLimitPolicy builds carries its brand
		const handBuilt: RateLimitPolicy = {
			limiter,
			tag: "types",
			failMode: "open",
			logger: consoleLogger,
		};
		expect(handBuilt.failMode).toBe("open");
	});
});
