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
import type { RateLimiterBase, RateLimiterFactory, RateLimitSpec } from "./types.mjs";

export function createRateLimiterFactory(): RateLimiterFactory {
	return createAdapterFactory<RateLimiterBase>("RateLimiter");
}

interface MemoryRateLimiterConfig {
	type: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
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

function keyPrefix(key: string): string {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
}

interface RedisRateLimiterConfig extends MemoryRateLimiterConfig {
	client?: {
		incr(key: string): Promise<number>;
		expire(key: string, seconds: number): Promise<number>;
	};
}

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

		interface BucketState {
			count: number;
			resetAt: number;
		}
		const buckets = new Map<string, BucketState>();

		return {
			kind: "memory",
			async check(key) {
				const now = Date.now();
				const spec = limits[keyPrefix(key)] ?? defaultLimit;
				const bucket = buckets.get(key);
				if (!bucket || bucket.resetAt <= now) {
					const fresh: BucketState = { count: 1, resetAt: now + spec.windowSeconds * 1000 };
					buckets.set(key, fresh);
					return { allowed: true, remaining: spec.limit - 1, resetAt: new Date(fresh.resetAt) };
				}
				if (bucket.count >= spec.limit) {
					return {
						allowed: false,
						remaining: 0,
						resetAt: new Date(bucket.resetAt),
						reason: `limit:${keyPrefix(key)}`,
					};
				}
				bucket.count += 1;
				return {
					allowed: true,
					remaining: spec.limit - bucket.count,
					resetAt: new Date(bucket.resetAt),
				};
			},
		};
	});

	factory.register("redis", async (rawConfig) => {
		const config = rawConfig as unknown as RedisRateLimiterConfig;
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
		const client =
			config.client ??
			(await (async () => {
				const { createClient } = await import("redis");
				const c = createClient();
				await c.connect();
				return {
					incr: (k: string) => c.incr(k) as Promise<number>,
					expire: (k: string, s: number) => c.expire(k, s) as Promise<number>,
				};
			})());

		return {
			kind: "redis",
			async check(key) {
				const spec = limits[keyPrefix(key)] ?? defaultLimit;
				const count = await client.incr(key);
				if (count === 1) {
					await client.expire(key, spec.windowSeconds);
				}
				if (count > spec.limit) {
					return {
						allowed: false,
						remaining: 0,
						reason: `limit:${keyPrefix(key)}`,
					};
				}
				return {
					allowed: true,
					remaining: spec.limit - count,
				};
			},
		};
	});
}
