import type { RateLimiter, RateLimitSpec } from "./types.mjs";
export declare const DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS = 10000;
export interface MemoryRateLimiterOptions {
    limits: Record<string, RateLimitSpec>;
    defaultLimit: RateLimitSpec;
    maxBuckets?: number;
}
export declare function createMemoryRateLimiter(options: MemoryRateLimiterOptions): RateLimiter;
//# sourceMappingURL=memory.d.mts.map