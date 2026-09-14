import type { SupportsLock } from "../types.mjs";
/**
 * Creates a single-process advisory lock usable by the in-memory
 * FederationTokenStore adapter. Not shared across processes — use
 * the redis lock (Task 3) for multi-process deployments.
 *
 * Stale entries (TTL-expired but never re-acquired) remain in the internal
 * Map until the next acquire of the same (sid, federationName) pair. For the
 * F-6 use case — one lock per active refresh cycle, TTL ≤ 5s — this is a
 * negligible bounded cost; deployments with very high distinct-session churn
 * and rare re-locks on the same federation can rely on process recycling
 * for final cleanup.
 */
export declare function createInProcessLock(): Pick<SupportsLock, "acquireLock">;
//# sourceMappingURL=memory.d.mts.map