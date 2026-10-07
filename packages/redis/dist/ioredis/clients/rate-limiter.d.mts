/**
 * The rate limiter's client over one ioredis connection: one script reads the count and its
 * `PTTL` after the increment and its expiry.
 */
import type { Redis } from "ioredis";
import type { RateLimiterClient } from "../../clients.mjs";
export declare function makeIoredisRateLimiterClient(io: Redis): RateLimiterClient;
//# sourceMappingURL=rate-limiter.d.mts.map