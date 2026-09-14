import type { ReplaySeenSet } from "../types.mjs";
/**
 * In-process Map-backed ReplaySeenSet. Same atomicity argument as the
 * memory ChallengeStore: Node.js single-event-loop + no awaits inside the
 * critical section between Map.get/check and Map.set/delete.
 *
 * GC is lazy (per-operation cleanup of expired entries). No background sweep.
 *
 * The `getLive` helper is deliberately duplicated rather than shared with
 * the memory ChallengeStore — three similar lines is preferable to a
 * premature abstraction here, since the two stores have semantically
 * distinct contracts (`issue` throws on duplicate; `markSeen` returns false
 * on duplicate). A shared helper would either branch on that distinction
 * (defeating the purpose) or share trivial Map+TTL plumbing only.
 *
 * Per A1 §7.1.
 */
export declare function createMemoryReplaySeenSet(): ReplaySeenSet;
//# sourceMappingURL=memory.d.mts.map