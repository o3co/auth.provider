import type { SupportsLock } from "@o3co/auth-provider-core";
/**
 * Minimal redis client shape the lock needs. Consumers can pass any client
 * that implements these three methods — node-redis, ioredis, fake clients in
 * tests, etc.
 *
 * ## Value-fidelity contract
 *
 * The compare-and-delete release path depends on two properties the lock
 * assumes of the client; consumers wiring a non-standard client MUST preserve
 * them:
 *
 * - `get(key)` MUST return the exact string previously written by `set(key, value)`.
 *   No normalization, wrapping, or transformation. Clients that base64-encode
 *   values on write must base64-decode on read (most commercial redis clients
 *   do this transparently; homemade shims must mirror the behavior).
 *
 * - `set(key, value, { NX: true, PX: ttlMs })` MUST return a truthy value (the
 *   stored string or `"OK"`) when the key was created, and MUST return `null`
 *   when creation was skipped because the key already exists. The lock treats
 *   any non-null return as acquire-success.
 *
 * - `PX` is in **milliseconds** (matching the redis native option).
 *
 * Breaking these invariants causes silent incorrectness: the release path
 * will fail its value-match check and never DEL, waiting for the TTL to
 * reclaim the key. Under load this manifests as lock starvation.
 */
export interface RedisLockClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, opts?: {
        PX?: number;
        NX?: boolean;
    }): Promise<string | null>;
    del(key: string): Promise<number>;
}
export interface RedisLockOptions {
    client: RedisLockClient;
    /** Default: "ftlock:" */
    keyPrefix?: string;
}
/**
 * Redis-backed advisory lock. Uses SET NX PX for acquire and compare-and-delete
 * for release — the release path fetches the current value and only issues DEL
 * when the value still matches the caller's acquire token, so a TTL-expired
 * caller cannot evict a subsequent holder.
 *
 * The compare-and-delete is GET + DEL — not atomic. A small race window exists
 * between the two commands, during which another process could acquire the
 * lock after our GET; our DEL would then evict them one poll-cycle early. The
 * window is ms-sized and the consequence is bounded — consumers that need
 * strict atomicity should upgrade to a Lua EVAL-based release.
 *
 * Plan line 837: "Upgrading to a Lua script would remove the race but adds
 * dependency on EVAL being available (which it is on all mainstream redis
 * versions). Defer unless pattern is reused heavily."
 */
export declare function createRedisLock(opts: RedisLockOptions): Pick<SupportsLock, "acquireLock">;
//# sourceMappingURL=lock.d.mts.map