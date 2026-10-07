import type { SessionFamilyIndex } from "../types.mjs";
/**
 * In-memory SessionFamilyIndex. Wraps `createMemorySidSortedSet` for
 * insertion-order-preserving, idempotent-add family-id tracking.
 *
 * Insertion order is informational (aids debugging / mirrors Redis ZRANGE
 * output) but NOT load-bearing for cascade revoke — callers iterate
 * order-independently. Per A4 §5.3 + §7.1.
 */
export declare function createInMemorySessionFamilyIndex(): SessionFamilyIndex;
//# sourceMappingURL=sessionFamilyIndex.d.mts.map