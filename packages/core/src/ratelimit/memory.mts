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

import type { RateLimiterBase, RateLimitSpec } from "./types.mjs";

export const DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS = 10_000;

interface BucketState {
	count: number;
	resetAt: number;
}

export interface MemoryRateLimiterOptions {
	limits: Record<string, RateLimitSpec>;
	defaultLimit: RateLimitSpec;
	maxBuckets?: number;
}

function keyPrefix(key: string): string {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
}

function normalizeMaxBuckets(value: number | undefined): number {
	return typeof value === "number" && Number.isInteger(value) && value > 0
		? value
		: DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS;
}

function pruneExpiredBuckets(buckets: Map<string, BucketState>, now: number): void {
	for (const [key, bucket] of buckets) {
		if (bucket.resetAt <= now) buckets.delete(key);
	}
}

function evictEarliestResetBucket(buckets: Map<string, BucketState>): void {
	let evictKey: string | undefined;
	let earliestResetAt = Number.POSITIVE_INFINITY;
	for (const [key, bucket] of buckets) {
		if (bucket.resetAt < earliestResetAt) {
			evictKey = key;
			earliestResetAt = bucket.resetAt;
		}
	}
	if (evictKey !== undefined) buckets.delete(evictKey);
}

export function createMemoryRateLimiter(options: MemoryRateLimiterOptions): RateLimiterBase {
	const buckets = new Map<string, BucketState>();
	const maxBuckets = normalizeMaxBuckets(options.maxBuckets);

	return {
		kind: "memory",
		async check(key) {
			const now = Date.now();
			const spec = options.limits[keyPrefix(key)] ?? options.defaultLimit;
			const bucket = buckets.get(key);
			if (!bucket || bucket.resetAt <= now) {
				if (!bucket && buckets.size >= maxBuckets) {
					pruneExpiredBuckets(buckets, now);
					while (buckets.size >= maxBuckets) evictEarliestResetBucket(buckets);
				}
				const fresh: BucketState = {
					count: 1,
					resetAt: now + spec.windowSeconds * 1000,
				};
				buckets.set(key, fresh);
				return {
					allowed: true,
					remaining: spec.limit - 1,
					resetAt: new Date(fresh.resetAt),
				};
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
}
