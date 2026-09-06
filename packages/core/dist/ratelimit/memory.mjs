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
export const DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS = 10_000;
function keyPrefix(key) {
    const colon = key.indexOf(":");
    return colon === -1 ? key : key.slice(0, colon);
}
function normalizeMaxBuckets(value) {
    return typeof value === "number" && Number.isInteger(value) && value > 0
        ? value
        : DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS;
}
function pruneExpiredBuckets(buckets, now) {
    for (const [key, bucket] of buckets) {
        if (bucket.resetAt <= now)
            buckets.delete(key);
    }
}
function evictEarliestResetBucket(buckets) {
    let evictKey;
    let earliestResetAt = Number.POSITIVE_INFINITY;
    for (const [key, bucket] of buckets) {
        // Non-finite resetAt (NaN / ±Infinity from a misconfigured
        // windowSeconds) is highest priority for removal: drop it eagerly so
        // the caller's `while (size >= max)` loop is guaranteed to make
        // progress and cannot pin the event loop. Without this, NaN < x
        // returns false for every comparison and evictKey stays undefined.
        if (!Number.isFinite(bucket.resetAt)) {
            buckets.delete(key);
            return;
        }
        if (bucket.resetAt < earliestResetAt) {
            evictKey = key;
            earliestResetAt = bucket.resetAt;
        }
    }
    if (evictKey !== undefined) {
        buckets.delete(evictKey);
        return;
    }
    // Defensive fallback: should be unreachable once the non-finite drop
    // above runs at least once per call, but keep eviction unconditionally
    // progress-guaranteed by deleting the first map entry. Map iteration
    // preserves insertion order, so this is the oldest bucket.
    const firstKey = buckets.keys().next().value;
    if (firstKey !== undefined)
        buckets.delete(firstKey);
}
export function createMemoryRateLimiter(options) {
    const buckets = new Map();
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
                    while (buckets.size >= maxBuckets)
                        evictEarliestResetBucket(buckets);
                }
                const fresh = {
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
