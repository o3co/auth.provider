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

function normalizeLimits(raw: unknown): Record<string, RateLimitSpec> {
	if (raw == null || typeof raw !== "object") return {};
	const result: Record<string, RateLimitSpec> = {};
	for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
		if (v && typeof v === "object" && "limit" in v && "windowSeconds" in v) {
			const spec = v as { limit: unknown; windowSeconds: unknown };
			if (typeof spec.limit === "number" && typeof spec.windowSeconds === "number") {
				result[k] = { limit: spec.limit, windowSeconds: spec.windowSeconds };
			}
		}
	}
	return result;
}

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
		const limits = normalizeLimits(config.limits);
		const defaultLimit: RateLimitSpec = (() => {
			const raw = config.defaultLimit;
			if (
				raw &&
				typeof raw === "object" &&
				typeof raw.limit === "number" &&
				typeof raw.windowSeconds === "number"
			) {
				return raw;
			}
			return { limit: 60, windowSeconds: 60 };
		})();

		return createMemoryRateLimiter({
			limits,
			defaultLimit,
			maxBuckets:
				typeof config.maxBuckets === "number"
					? config.maxBuckets
					: DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
		});
	});
}
