import type { FederationTokenStoreClient } from "../clients.mjs";
/**
 * The slice of `FederationTokenStoreClient` this helper consumes. Named after
 * its consumer, like `SessionRPRegistryClient` and `SessionSidSortedSetClient`
 * are for the other two sid-keyed helpers.
 */
export type RedisSidSetClient = Pick<FederationTokenStoreClient, "sAddWithTtl" | "sRem" | "sScanIterator" | "unlink">;
export interface RedisSidSetOptions {
    readonly client: RedisSidSetClient;
    readonly keyPrefix: string;
    /**
     * Members requested per `SSCAN` round-trip. A hint to Redis, not a hard
     * limit on a page's size. Default 100 — the batch size the federation
     * token store already used for its delete batches.
     *
     * Must be a positive integer — Redis refuses a non-positive `COUNT`.
     * Validated at construction rather than discovered mid-logout.
     */
    readonly scanCount?: number;
}
export interface RedisSidSet {
    add(sid: string, member: string, ttlMs: number): Promise<void>;
    remove(sid: string, member: string): Promise<void>;
    /** Cursor-based iteration over the sid's members. May yield duplicates. */
    members(sid: string): AsyncIterable<string>;
    removeBySid(sid: string): Promise<void>;
}
/**
 * Private redis helper: a sid-keyed SET at `${keyPrefix}${sid}`, third in the
 * family alongside `createRedisSidHash` (HASH) and `createRedisSidSortedSet`
 * (ZSET). Same key layout, same TTL contract, different Redis type — a SET is
 * what an unordered membership index of "which names exist under this sid"
 * actually is.
 *
 * Introduced for #291. The federation token store used to answer
 * "which federations does this sid have?" with `SCAN MATCH ft:<sid>:*`, which
 * is O(keys in the database) and runs on an end-user logout. This index
 * answers it in O(the session's federations).
 *
 * **TTL contract**: unlike its two siblings the caller passes a *relative*
 * `ttlMs`, not `session.expiresAt` — the federation token store's records live
 * on a fixed store TTL (an upper bound that must outlive the upstream
 * refresh_token), not on the session's expiry. `sAddWithTtl` applies the same
 * `PEXPIRE … NX` + `PEXPIRE … GT` pair the siblings use, so the index key
 * always outlives the envelopes it points at and no write can truncate a
 * further deadline. Atomicity of the add and its expiry is part of the client
 * contract rather than this helper's discipline: a persistent index key
 * outlives the session it describes.
 *
 * **Reads are paginated** (`SSCAN`), so a session linked to an unbounded
 * number of providers is walked in pages instead of materialised by one
 * `SMEMBERS`. `SSCAN` may return a member more than once; callers here only
 * ever delete, which is idempotent.
 *
 * **Removal is `UNLINK`**, not `DEL`: freeing the key is not worth blocking
 * the shared connection during a logout.
 */
export declare function createRedisSidSet(opts: RedisSidSetOptions): RedisSidSet;
//# sourceMappingURL=redisSidSet.d.mts.map