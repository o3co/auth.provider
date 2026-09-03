/**
 * Backing client for ChallengeStore adapters. Adapter implementations
 * (e.g. `createRedisChallengeStore`) consume exactly these methods.
 */
export interface ChallengeStoreClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    pttl(key: string): Promise<number>;
    del(key: string): Promise<number>;
}
/**
 * Backing client for ReplaySeenSet adapters. Adapter implementations
 * (e.g. `createRedisReplaySeenSet`) consume exactly these methods.
 */
export interface ReplaySeenSetClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    exists(key: string): Promise<number>;
}
/**
 * Chainable transaction pipeline returned by `RefreshTokenFamilyClient.multi()`.
 */
export interface RefreshTokenFamilyMultiClient {
    set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
    exec(): Promise<unknown[] | null>;
}
/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation per A3 §7.2.
 */
export interface RefreshTokenFamilyClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    get(key: string): Promise<string | null>;
    pttl(key: string): Promise<number>;
    watch(...keys: string[]): Promise<"OK">;
    unwatch(): Promise<"OK">;
    multi(): RefreshTokenFamilyMultiClient;
    duplicate(): DisposableRefreshTokenFamilyClient;
}
/**
 * A `RefreshTokenFamilyClient` that owns a single network connection and is
 * responsible for closing it. Returned by `RefreshTokenFamilyClient.duplicate()`
 * so consumer code can use `await using conn = client.duplicate()` for scoped,
 * exception-safe connection lifetime.
 */
export interface DisposableRefreshTokenFamilyClient extends RefreshTokenFamilyClient, AsyncDisposable {
    [Symbol.asyncDispose](): Promise<void>;
}
/**
 * Backing client for UserSessionStore adapters. Declares only `set`, `get`,
 * `del` — the exact methods `createRedisUserSessionStore` consumes.
 *
 * `set` has two overloads:
 *  - plain PX form (no condition): always succeeds with `"OK"` per Redis
 *    `SET key value PX ms` protocol; never returns null.
 *  - PX+NX form: atomic insert-only, used by `create`; mirrors
 *    ChallengeStore.issue and RefreshTokenFamilyStore.registerFamily.
 *    Returns `"OK"` on insert, `null` when the key already existed.
 */
export interface UserSessionStoreClient {
    set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    get(key: string): Promise<string | null>;
    del(key: string): Promise<number>;
}
/**
 * Chainable transaction pipeline returned by `SessionRPRegistryClient.multi()`.
 */
export interface SessionRPRegistryMultiClient {
    hSet(key: string, field: string, value: string): SessionRPRegistryMultiClient;
    pExpireAt(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
    exec(): Promise<unknown[] | null>;
}
/**
 * Backing client for SessionRPRegistry adapters. Declares the hash ops +
 * multi pipeline that `createRedisSidHash` consumes.
 */
export interface SessionRPRegistryClient {
    del(key: string): Promise<number>;
    hSet(key: string, field: string, value: string): Promise<number>;
    hVals(key: string): Promise<string[]>;
    multi(): SessionRPRegistryMultiClient;
    pExpireAt(key: string, msTimestamp: number): Promise<number>;
}
/**
 * Chainable transaction pipeline returned by `SessionSidSortedSetClient.multi()`.
 */
export interface SessionSidSortedSetMultiClient {
    pExpireAt(key: string, msTimestamp: number): SessionSidSortedSetMultiClient;
    zAdd(key: string, entry: {
        score: number;
        value: string;
    }, opts?: {
        NX: true;
    }): SessionSidSortedSetMultiClient;
    exec(): Promise<unknown[] | null>;
}
/**
 * Backing client for SessionFamilyIndex and SessionFederationIndex adapters.
 * Both adapters share this interface (same sorted-set operations, different
 * slot identities in ComponentMap).
 */
export interface SessionSidSortedSetClient {
    del(key: string): Promise<number>;
    multi(): SessionSidSortedSetMultiClient;
    pExpireAt(key: string, msTimestamp: number): Promise<number>;
    zAdd(key: string, entry: {
        score: number;
        value: string;
    }, opts?: {
        NX: true;
    }): Promise<number>;
    zRange(key: string, start: number, stop: number): Promise<string[]>;
    zRem(key: string, member: string): Promise<number>;
}
/**
 * Backing client for FederationTokenStore adapters. Declares `get`, `set`
 * (two overloads: PX form, and PX+NX form for atomic insert-only),
 * variadic `del`, and `scanIterator` for the cursor-based key scan used
 * by `deleteBySession`.
 *
 * The plain-PX `set` overload always succeeds with `"OK"` per Redis
 * `SET key value PX ms` protocol; the PX+NX overload returns `"OK"` on
 * insert or `null` when the key already existed.
 */
export interface FederationTokenStoreClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    del(...keys: string[]): Promise<number>;
    scanIterator(opts: {
        MATCH: string;
        COUNT?: number;
    }): AsyncIterable<string>;
}
/**
 * Backing client for RateLimiter adapters. Declares only `incr` and `expire`
 * — the two methods `createRedisRateLimiter` consumes.
 */
export interface RateLimiterClient {
    incr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly challengeStoreClient?: ChallengeStoreClient;
        readonly replaySeenSetClient?: ReplaySeenSetClient;
        readonly refreshTokenFamilyClient?: RefreshTokenFamilyClient;
        readonly userSessionStoreClient?: UserSessionStoreClient;
        readonly sessionRPRegistryClient?: SessionRPRegistryClient;
        readonly sessionFamilyIndexClient?: SessionSidSortedSetClient;
        readonly sessionFederationIndexClient?: SessionSidSortedSetClient;
        readonly federationTokenStoreClient?: FederationTokenStoreClient;
        readonly rateLimiterClient?: RateLimiterClient;
    }
}
//# sourceMappingURL=clients.d.mts.map