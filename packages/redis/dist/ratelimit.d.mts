import { type AdapterBuilder, type RateLimiterBase, type RateLimitSpec } from "@o3co/auth-provider-core";
import type { RateLimiterClient } from "./clients.mjs";
interface CreateRedisRateLimiterOptions {
    client: RateLimiterClient;
    limits?: Record<string, RateLimitSpec>;
    defaultLimit?: RateLimitSpec;
}
/**
 * Redis-backed RateLimiter. Atomic INCR with TTL set on first hit. Consumer
 * passes their own redis client because RateLimiterBase has no dispose
 * lifecycle hook — client lifetime lives in the composition root alongside
 * other redis users.
 */
export declare function createRedisRateLimiter(opts: CreateRedisRateLimiterOptions): RateLimiterBase;
/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisRateLimiterBuilder);
 */
export declare const redisRateLimiterBuilder: AdapterBuilder<RateLimiterBase>;
/**
 * `defineModule` manifest for the redis RateLimiter. Reads `redisRateLimiter`
 * config slice (limits + defaultLimit). The redis client itself comes from
 * the `rateLimiterClient` ComponentMap slot (per-purpose interface declared
 * in `@o3co/auth-provider-core`'s `ratelimit/types.mts`).
 */
export declare const redisRateLimiterModule: import("@o3co/auth-provider-core").Module;
export {};
//# sourceMappingURL=ratelimit.d.mts.map