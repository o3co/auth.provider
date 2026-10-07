import type { FederationTokenStoreBase, SupportsLock } from "../types.mjs";
export interface RedisLikeClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, opts?: {
        PX?: number;
        NX?: boolean;
    }): Promise<string | null>;
    del(...keys: string[]): Promise<number>;
    /**
     * Non-blocking alternative to Redis KEYS — matches redis v5 client's
     * `scanIterator({ MATCH, COUNT })`. Cursor-based, yields matching keys in
     * batches without blocking the server. Required for `deleteBySession` to
     * be safe in production.
     */
    scanIterator(opts: {
        MATCH: string;
        COUNT?: number;
    }): AsyncIterable<string>;
}
export type EncryptionConfig = {
    mode: "required";
    key: Buffer;
} | {
    mode: "allow-plaintext";
};
export interface RedisFederationTokenStoreOptions {
    client: RedisLikeClient;
    encryption: EncryptionConfig;
    keyPrefix?: string;
    /**
     * Redis key TTL in seconds. This is the upper bound on how long a federation
     * token record persists; it MUST exceed the upstream federation refresh_token
     * lifetime so that refresh flows (F-6) can still retrieve the refresh_token
     * after the access_token has expired.
     *
     * Do NOT tie this TTL to `tokens.expiresAt` (the access_token expiry) —
     * access_token expiry is kept inside the envelope for F-6 to consult at
     * retrieval time, but the record itself lives until this store TTL elapses.
     *
     * Default: 86400 seconds (24 hours). Spec Section 5.2.
     */
    ttl?: number;
}
export declare function createRedisFederationTokenStore(opts: RedisFederationTokenStoreOptions): FederationTokenStoreBase & SupportsLock;
//# sourceMappingURL=redis.d.mts.map