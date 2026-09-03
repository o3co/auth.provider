import type { SessionFederationIndex } from "@o3co/auth-provider-core";
import type { SessionSidSortedSetClient } from "./clients.mjs";
export interface RedisSessionFederationIndexOptions {
    readonly client: SessionSidSortedSetClient;
    readonly keyPrefix: string;
}
/**
 * Redis-backed SessionFederationIndex. Wraps `createRedisSidSortedSet` (ZSET
 * with insertion-time score, ZADD NX). Per A4 §5.4 + §7.2.
 *
 * Ordering contract (load-bearing): `listFederations(sid)` returns federation
 * names in INSERTION order (oldest first). `routes/logout.mts` uses the first
 * element for IdP post-logout redirect. ZADD NX preserves original
 * insertion-time score so re-add of an existing member does NOT promote its
 * position.
 *
 * `removeFederation(sid, name)` delegates to `RedisSidSortedSet.remove` for
 * per-element removal (required for federation logout completion, distinct from
 * full-session `removeBySid`).
 */
export declare function createRedisSessionFederationIndex(opts: RedisSessionFederationIndexOptions): SessionFederationIndex;
//# sourceMappingURL=sessionFederationIndex.d.mts.map