import type { SessionSidSortedSetClient } from "../clients.mjs";
export interface RedisSidSortedSetOptions {
    readonly client: SessionSidSortedSetClient;
    readonly keyPrefix: string;
}
export interface RedisSidSortedSet {
    add(sid: string, member: string, expiresAt: Date): Promise<void>;
    list(sid: string): Promise<string[]>;
    remove(sid: string, member: string): Promise<void>;
    removeBySid(sid: string): Promise<void>;
}
/**
 * Private redis helper used by `SessionFamilyIndex` + `SessionFederationIndex`.
 * Single-key ZADD NX + PEXPIREAT pipeline keyed by `${keyPrefix}${sid}`.
 *
 * Per A4 §7.2.2.
 *
 * **NX semantics**: ZADD ... NX does NOT update the existing member's score.
 * Original insertion-time score is preserved, so re-add of an existing
 * member does NOT promote its position. Load-bearing for
 * `SessionFederationIndex` ordering contract (A4 §5.4).
 *
 * **TTL contract** (identical to `createRedisSidHash`): callers MUST pass
 * `session.expiresAt`; same-sid writes use the SAME `expiresAt`; writes
 * after expiry no-op.
 *
 * **Score**: monotonic module-level counter (see `_insertionCounter` above).
 * The counter replaces `Date.now()` as the score source to guarantee strict
 * insertion-order even when multiple adds execute within the same millisecond.
 */
export declare function createRedisSidSortedSet(opts: RedisSidSortedSetOptions): RedisSidSortedSet;
//# sourceMappingURL=redisSidSortedSet.d.mts.map