/**
 * Private memory helper used by `SessionFamilyIndex` + `SessionFederationIndex`.
 * Mirrors the Redis `createRedisSidSortedSet` semantics: insertion-order
 * preserving (ZADD NX equivalent), TTL-synced to `expiresAt`, no-op writes
 * after expiry, per-member remove. Per A4 §7.1 (lines 533-565 of the spec).
 *
 * Insertion-order is load-bearing for `SessionFederationIndex` per A4 §5.4
 * (orchestrator reads `(await listFederations(sid))[0]` to choose the IdP
 * for post-logout redirect).
 */
export interface MemorySidSortedSet {
    add(sid: string, member: string, expiresAt: Date): void;
    list(sid: string): string[];
    remove(sid: string, member: string): void;
    removeBySid(sid: string): void;
}
export declare function createMemorySidSortedSet(): MemorySidSortedSet;
//# sourceMappingURL=internalSidSortedSet.d.mts.map