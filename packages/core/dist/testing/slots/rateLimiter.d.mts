/**
 * The test double of the `RateLimiter` port, the `rateLimiter` slot's
 * value. `createTestRateLimiter` records every key checked, allows every
 * check or counts each key against a limit, and can stand in for a backend
 * that is down. The port's contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { RateLimiter, RateLimitFailMode } from "../../ratelimit/types.mjs";
export interface TestRateLimiterOptions {
    /** The limiter's outage policy. Absent, it declares none. */
    readonly failMode?: RateLimitFailMode;
    /** How many checks each key is allowed; absent, every check is. Never reset. */
    readonly limit?: number;
}
/** A `RateLimiter` for tests. */
export interface TestRateLimiter extends RateLimiter {
    readonly kind: "test";
    /** Every key checked, oldest first. */
    readonly checked: readonly string[];
    /** From now on every check rejects with `error` and counts nothing: a backend that is down. */
    failWith(error: unknown): void;
    /** Answer again. */
    recover(): void;
}
export declare function createTestRateLimiter(options?: TestRateLimiterOptions): TestRateLimiter;
//# sourceMappingURL=rateLimiter.d.mts.map