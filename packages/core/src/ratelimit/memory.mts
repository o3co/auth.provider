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

import type { RateLimiter, RateLimitSpec } from "./types.mjs";
import { assertUsableRateLimitSpecs } from "./usableSpec.mjs";

export const DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS = 10_000;

interface BucketState {
	count: number;
	resetAt: number;
}

export interface MemoryRateLimiterOptions {
	/** Specs by key prefix. Not given is none, as the Redis adapter reads it. */
	limits?: Record<string, RateLimitSpec>;
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

/**
 * Removes the bucket that resets first. Every `resetAt` is finite: it is
 * `Date.now()` plus a window construction checked, from specs the limiter
 * holds as it checked them. And a non-empty map always loses one bucket,
 * since the first entry is taken before any comparison, so the caller's
 * `while (size >= max)` loop always makes progress.
 */
function evictEarliestResetBucket(buckets: Map<string, BucketState>): void {
	let evictKey: string | undefined;
	let earliestResetAt = 0;
	for (const [key, bucket] of buckets) {
		if (evictKey === undefined || bucket.resetAt < earliestResetAt) {
			evictKey = key;
			earliestResetAt = bucket.resetAt;
		}
	}
	if (evictKey !== undefined) buckets.delete(evictKey);
}

export function createMemoryRateLimiter(options: MemoryRateLimiterOptions): RateLimiter {
	// A spec this limiter cannot apply as written is refused here, by the
	// predicate the Redis adapter refuses it by: kept, a zero window reset on
	// every check and never limited anything, and a NaN one reset at an
	// Invalid Date. The default is not optional here.
	if (options.defaultLimit === undefined) {
		throw new RangeError("createMemoryRateLimiter: defaultLimit is required");
	}
	assertUsableRateLimitSpecs("createMemoryRateLimiter", options);
	// Held as they were checked, as the Redis adapter holds them: a change to
	// the objects it was handed cannot reach a check. A missing `limits` is
	// none; a present one that is not an object was refused above.
	const limits: Readonly<Record<string, RateLimitSpec>> = Object.fromEntries(
		Object.entries(options.limits ?? {}).map(([prefix, spec]) => [
			prefix,
			{ limit: spec.limit, windowSeconds: spec.windowSeconds },
		]),
	);
	const defaultLimit: RateLimitSpec = {
		limit: options.defaultLimit.limit,
		windowSeconds: options.defaultLimit.windowSeconds,
	};
	const buckets = new Map<string, BucketState>();
	const maxBuckets = normalizeMaxBuckets(options.maxBuckets);

	return {
		kind: "memory",
		async check(key) {
			const now = Date.now();
			const spec = limits[keyPrefix(key)] ?? defaultLimit;
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
					limit: spec.limit,
				};
			}
			if (bucket.count >= spec.limit) {
				return {
					allowed: false,
					remaining: 0,
					resetAt: new Date(bucket.resetAt),
					reason: `limit:${keyPrefix(key)}`,
					limit: spec.limit,
				};
			}
			bucket.count += 1;
			return {
				allowed: true,
				remaining: spec.limit - bucket.count,
				resetAt: new Date(bucket.resetAt),
				limit: spec.limit,
			};
		},
	};
}
