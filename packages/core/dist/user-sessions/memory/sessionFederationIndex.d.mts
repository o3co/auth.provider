import type { SessionFederationIndex } from "../types.mjs";
/**
 * In-memory SessionFederationIndex. Wraps `createMemorySidSortedSet` for
 * insertion-order-preserving, idempotent-add federation name tracking.
 *
 * Insertion order is LOAD-BEARING per A4 §5.4: the cascade orchestrator reads
 * `(await listFederations(sid))[0]` to choose the IdP for post-logout redirect.
 * Re-add of an existing member does NOT promote position (ZADD NX equivalent).
 *
 * Supports per-element `removeFederation(sid, name)` for federation logout
 * completion in addition to full `removeBySid` cleanup. Per A4 §5.4 + §7.1.
 */
export declare function createInMemorySessionFederationIndex(): SessionFederationIndex;
//# sourceMappingURL=sessionFederationIndex.d.mts.map