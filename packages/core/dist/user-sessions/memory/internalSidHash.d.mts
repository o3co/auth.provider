/**
 * Private memory helper used by `SessionRPRegistry`. Mirrors the Redis
 * `createRedisSidHash` semantics: id-keyed upsert under a single sid-scoped
 * envelope, TTL-synced to `expiresAt`, no-op writes after expiry. Per A4 §7.1
 * (lines 510-531 of the spec).
 */
export interface MemorySidHash<T> {
    setField(sid: string, entry: T, expiresAt: Date): void;
    listValues(sid: string): T[];
    removeBySid(sid: string): void;
}
export declare function createMemorySidHash<T>(idOf: (t: T) => string): MemorySidHash<T>;
//# sourceMappingURL=internalSidHash.d.mts.map