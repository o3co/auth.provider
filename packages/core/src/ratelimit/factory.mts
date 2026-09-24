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

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryRateLimiter, DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS } from "./memory.mjs";
import type { RateLimiter, RateLimiterFactory, RateLimitSpec } from "./types.mjs";

export function createRateLimiterFactory(): RateLimiterFactory {
	return createAdapterFactory<RateLimiter>("RateLimiter");
}

interface MemoryRateLimiterConfig {
	type: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	maxBuckets?: number;
}

/** The built-in default, for a configuration that gives none. */
const DEFAULT_LIMIT: RateLimitSpec = { limit: 60, windowSeconds: 60 };

/**
 * Registers the built-in in-memory RateLimiter. The "redis" backend was
 * relocated to `@o3co/auth-provider-redis` in Phase 10; consumers wire it via:
 *
 *   import { redisRateLimiterBuilder } from "@o3co/auth-provider-redis";
 *   factory.register("redis", redisRateLimiterBuilder);
 *
 * Or use the declarative `redisRateLimiterModule` in their `modules` array.
 */
export function registerBuiltinRateLimiters(factory: RateLimiterFactory): void {
	factory.register("memory", (rawConfig) => {
		const config = rawConfig as unknown as MemoryRateLimiterConfig;
		// What was configured, as it was: `createMemoryRateLimiter` refuses a
		// spec it cannot apply as written. This used to drop such a spec, or put
		// its own default in for a malformed one — a looser budget than the
		// operator wrote, and a different one from the Redis adapter's answer.
		// Only a default nobody gave is the built-in 60 per 60 s.
		return createMemoryRateLimiter({
			limits: (config.limits ?? {}) as Record<string, RateLimitSpec>,
			defaultLimit: config.defaultLimit === undefined ? DEFAULT_LIMIT : config.defaultLimit,
			maxBuckets:
				typeof config.maxBuckets === "number"
					? config.maxBuckets
					: DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
		});
	});
}
