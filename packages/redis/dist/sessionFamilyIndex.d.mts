import type { SessionFamilyIndex } from "@o3co/auth-provider-core";
import type { SessionSidSortedSetClient } from "./clients.mjs";
export interface RedisSessionFamilyIndexOptions {
    readonly client: SessionSidSortedSetClient;
    readonly keyPrefix: string;
}
/**
 * Redis-backed SessionFamilyIndex. Wraps `createRedisSidSortedSet` (ZSET
 * with insertion-time score, ZADD NX). Per A4 §5.3 + §7.2.
 *
 * Order is informational for cascade revoke (caller iterates
 * order-independently); the helper choice is made for consistency with
 * `SessionFederationIndex` rather than functional dependency.
 */
export declare function createRedisSessionFamilyIndex(opts: RedisSessionFamilyIndexOptions): SessionFamilyIndex;
//# sourceMappingURL=sessionFamilyIndex.d.mts.map