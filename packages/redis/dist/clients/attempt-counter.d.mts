/**
 * The attempt counter's client: one attempt counted against a fixed window as one indivisible
 * step, and what its server says about evicting keys.
 */
import type { RedisDurability } from "./durability.mjs";
/** What {@link AttemptCounterClient.consume} is handed besides the key. */
export interface AttemptCounterConsumeInput {
    /** The caller's clock, whole epoch milliseconds: a window is running while its end is after it. */
    readonly nowMs: number;
    /** The most attempts a window allows, judged on this attempt. */
    readonly limit: number;
    /** Where a window this attempt opens ends, whole epoch milliseconds. */
    readonly resetAtMs: number;
    /**
     * How long past its end, in milliseconds, the key of a window this attempt opens lives. The
     * key's TTL is relative (`PEXPIRE` of `resetAtMs − nowMs` plus this), so the server's clock
     * never decides when a running window is freed.
     */
    readonly expiryAllowanceMs: number;
}
/** What {@link AttemptCounterClient.consume} answers. */
export interface AttemptCounterConsumeReply {
    /** The attempt was counted. */
    readonly allowed: boolean;
    /** Attempts counted in the window, this one included when allowed. */
    readonly count: number;
    /** Where the window the attempt fell in ends, epoch milliseconds. */
    readonly resetAtMs: number;
}
/**
 * Backing client for the Redis `AttemptCounter`. One method, because reading
 * the window, counting the attempt and setting the key's deadline must be one
 * indivisible step, or concurrent attempts are counted past the limit.
 */
export interface AttemptCounterClient {
    /**
     * Count one attempt under `key`, **atomically**:
     *
     *   - a window is running when the key holds a count and an end, and
     *     either the end is after `nowMs` or the key's remaining TTL is above
     *     `expiryAllowanceMs` (the server's countdown, which a caller's clock
     *     running ahead cannot end early: such a caller is answered the running
     *     window's end, never a fresh window); then the attempt is allowed and
     *     counted while the count is below `limit`, and refused otherwise,
     *     writing nothing
     *   - with no window running, open one: count 1, ending at `resetAtMs`,
     *     the key's TTL `resetAtMs − nowMs + expiryAllowanceMs`
     *   - a running window's end and TTL are never moved
     */
    consume(key: string, input: AttemptCounterConsumeInput): Promise<AttemptCounterConsumeReply>;
    /** What the server says about evicting and keeping keys, read once by the factory for its eviction gate. */
    durability(): Promise<RedisDurability>;
}
//# sourceMappingURL=attempt-counter.d.mts.map