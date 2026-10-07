import type { ChallengeStore } from "../types.mjs";
/**
 * In-process Map-backed ChallengeStore. Atomicity comes from the Node.js
 * single-event-loop guarantee: synchronous Map.get → check → Map.set/Map.delete
 * blocks contain NO `await`, so concurrent calls cannot interleave at micro-
 * task boundaries.
 *
 * GC is lazy (per-operation cleanup of expired entries). No background sweep.
 *
 * Per A1 §7.1.
 */
export declare function createMemoryChallengeStore(): ChallengeStore;
//# sourceMappingURL=memory.d.mts.map