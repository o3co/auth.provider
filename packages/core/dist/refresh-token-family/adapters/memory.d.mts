import type { RefreshTokenFamilyStore } from "../types.mjs";
/**
 * Memory-backed RefreshTokenFamilyStore.
 *
 * Atomicity argument (single-process, single-event-loop):
 *   - All read/check/write sequences inside `registerFamily` and
 *     `updateFamily` are SYNCHRONOUS — there is no `await` between the
 *     Map.get (or Map.has) and the Map.set (or Map.delete). Node's
 *     microtask queue cannot interleave non-async work, so concurrent
 *     callers do not race.
 *   - CAS conflict cannot occur (no cross-instance concurrency); the
 *     memory adapter therefore never throws "conflict-exhausted".
 *
 * Lazy GC: an expired entry is removed on the next access via getLive().
 *
 * Per A3 §7.1.
 */
export declare function createMemoryRefreshTokenFamilyStore(): RefreshTokenFamilyStore;
//# sourceMappingURL=memory.d.mts.map