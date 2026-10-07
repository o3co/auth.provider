/**
 * The rate limiter's client: a counter's increment and its expiry as one indivisible step.
 */
/**
 * Backing client for RateLimiter adapters. One method, because the increment
 * and its expiry have to happen together: with a separate `expire`, a process
 * death or an `expire` error in between leaves the key with **no TTL at
 * all**, so it never resets and that key's client is 429'd permanently — and
 * `failMode` cannot help, since the check itself succeeds. One method puts
 * atomicity in the contract, where an implementation cannot omit it.
 */
export interface RateLimiterClient {
    /**
     * Increment `key`'s counter and return the new value, ensuring the key
     * carries a TTL — **atomically**, as one indivisible operation:
     *
     *   - increment the counter, creating the key at 1 when absent
     *   - if the key has no expiry, set it to `ttlSeconds`
     *   - if the key already has one, leave it alone: the window starts at the
     *     first request, and refreshing it on every hit would let a steady
     *     stream of traffic hold a counter open indefinitely
     *   - return the post-increment count
     *
     * Setting the expiry when it is *missing*, rather than when the count is 1,
     * repairs a key already stranded without one, whose count never returns to
     * 1. Lua is the obvious implementation (see `makeIoredisClients`);
     * anything indivisible satisfies the contract.
     *
     * @param ttlSeconds Window length. Always a positive integer — callers
     *   reject non-positive specs, because `EXPIRE key 0` deletes the key and
     *   would turn the limiter into a no-op.
     */
    incrementWithTtl(key: string, ttlSeconds: number): Promise<number>;
    /**
     * `incrementWithTtl`, also returning the counter key's `PTTL` after the
     * increment, read in the same indivisible step. The limiter turns it into
     * `RateLimitDecision.resetAt`, and the guard turns that into the
     * `Retry-After` on a 429.
     *
     * Optional so a custom client written against the one-method contract
     * keeps compiling and working; a limiter given such a client reports no
     * reset time.
     */
    incrementWithTtlAndPttl?(key: string, ttlSeconds: number): Promise<RateLimitIncrement>;
}
/** What {@link RateLimiterClient.incrementWithTtlAndPttl} answers. */
export interface RateLimitIncrement {
    /** The post-increment count. */
    readonly count: number;
    /** The counter key's remaining TTL in milliseconds (`PTTL`), read after the increment. */
    readonly pttl: number;
}
//# sourceMappingURL=rate-limiter.d.mts.map