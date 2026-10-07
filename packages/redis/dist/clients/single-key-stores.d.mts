/**
 * Clients for the stores that keep each record as one string key with a `PX` expiry:
 * challenges, the access-token denylist, the replay seen-set and authorization codes.
 */
import type { RedisDurability } from "./durability.mjs";
/**
 * Backing client for ChallengeStore adapters. Adapter implementations
 * (e.g. `createRedisChallengeStore`) consume exactly these methods.
 */
export interface ChallengeStoreClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    pttl(key: string): Promise<number>;
    del(key: string): Promise<number>;
    /** Reads a challenge's value, which carries when it was issued. */
    get(key: string): Promise<string | null>;
}
/**
 * Backing client for AccessTokenDenylist adapters
 * (`createRedisAccessTokenDenylist`).
 *
 * `set` is the plain PX form with no `NX`: re-revoking a jti is idempotent and
 * last-write-wins on the expiry, matching the memory adapter. That is also why
 * this is separate from {@link ReplaySeenSetClient}, whose whole contract
 * turns on the `NX` return value.
 */
export interface AccessTokenDenylistClient {
    set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
    exists(key: string): Promise<number>;
    /**
     * What the server says about keeping what it is written, read once by the
     * store's factory for its eviction gate: a revoked jti evicted before its
     * expiry reads as not revoked.
     */
    durability(): Promise<RedisDurability>;
}
/**
 * Backing client for ReplaySeenSet adapters. Adapter implementations
 * (e.g. `createRedisReplaySeenSet`) consume exactly these methods.
 */
export interface ReplaySeenSetClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    exists(key: string): Promise<number>;
    /**
     * What the server says about keeping what it is written, read once by the
     * seen-set's factory for its eviction gate: a value evicted before its
     * window ends reads as never seen.
     */
    durability(): Promise<RedisDurability>;
}
/**
 * Backing client for CodeRepository adapters: the four Redis commands
 * `RedisCodeRepository` consumes — `set` with PX expiry (always `"OK"`),
 * unconditional `get`, atomic `getDel` (Redis 6.2+), and unconditional
 * `del`. The repository consumes this externally provided wrapper (via
 * `bootstrapComponents`) instead of constructing its own client.
 */
export interface CodeRepositoryClient {
    set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
    get(key: string): Promise<string | null>;
    getDel(key: string): Promise<string | null>;
    del(key: string): Promise<number>;
}
//# sourceMappingURL=single-key-stores.d.mts.map