import type { UserSessionStoreBase } from "../types.mjs";
/**
 * The subset of the `redis` v5 client used by this adapter. Matching a subset
 * lets us mock the client in tests without importing the real package.
 */
export interface RedisLikeClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, opts?: {
        PX?: number;
        NX?: boolean;
    }): Promise<string | null>;
    del(key: string): Promise<number>;
}
export interface RedisUserSessionStoreOptions {
    client: RedisLikeClient;
    keyPrefix?: string;
}
export declare function createRedisUserSessionStore(opts: RedisUserSessionStoreOptions): UserSessionStoreBase;
//# sourceMappingURL=redis.d.mts.map