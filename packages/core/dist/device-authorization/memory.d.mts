/**
 * In-process `DeviceCodeStore`. Development and single-replica only.
 *
 * Registered in `REPLICA_UNSAFE_MODULE_REASONS`: a device that polls a
 * different replica than the one holding its record is told its code does not
 * exist, and the human's approval lands on a replica the device may never
 * reach again.
 *
 * The atomicity the port demands is free here — JavaScript's single-threaded
 * event loop means the body of each method runs without interleaving — but
 * the *shape* still matters, because it is the shape a Redis adapter has to
 * reproduce in a script rather than discover it needed to.
 *
 * ### Bounded, three ways
 *
 * The first cut was unbounded in practice: the module built it with no
 * `sweepIntervalMs`, so the timer was null; `findPendingByUserCode`,
 * `approve` and `deny` answered "expired" without dropping the record; only
 * `poll` reclaimed. A device that asks for a code and never polls — or a
 * caller who asks for ten thousand — left records resident until exit.
 *
 * Same fix the access-token denylist got (#293 item 6), plus the cap the
 * rate limiter already had:
 *
 *   1. every read path drops an expired record it finds, so the ordinary
 *      traffic of a verification page reclaims as it goes;
 *   2. `create` — the one operation that grows the map — pays for the growth
 *      with an amortized sweep every `sweepInterval` creates, so a record
 *      nobody asks about again is reclaimed within one interval;
 *   3. `maxEntries` caps the resident set outright. At the cap, expired
 *      records are pruned first; if the set is still full, the live record
 *      closest to expiry is evicted — the least harm under a flood, since it
 *      is the one about to be reclaimed anyway.
 *
 * The optional timer stays for deployments that want zero-lag reclamation;
 * it is no longer what bounds the store.
 */
import type { DeviceCodeStore } from "./types.mjs";
/**
 * Ceiling on resident records. Ten thousand pending device authorizations is
 * far past what a single-replica deployment serves in one code lifetime, and
 * at a few hundred bytes each it is a bound an operator never notices.
 */
export declare const DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES = 10000;
/**
 * `create` calls between amortized sweeps. A sweep is O(size), and every
 * create is one rate-limited HTTP request, so the cost per request stays
 * constant while the resident set is bounded at "live records, plus at most
 * one interval of expired ones".
 */
export declare const DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL = 1000;
export interface MemoryDeviceCodeStoreOptions {
    /**
     * How often to sweep expired entries on a timer, in milliseconds. Off by
     * default: the amortized sweep on `create` and the reclaim-on-read paths
     * already bound the store, so the timer buys only zero-lag reclamation.
     */
    readonly sweepIntervalMs?: number;
    /**
     * Ceiling on resident records. A non-integer or non-positive value falls
     * back to the default rather than removing the cap — `0` is what an empty
     * environment variable coerces to.
     */
    readonly maxEntries?: number;
    /**
     * `create` calls between amortized sweeps. Same fallback rule as
     * `maxEntries`: a bad value must not disable the sweep.
     */
    readonly sweepInterval?: number;
}
export interface MemoryDeviceCodeStore extends DeviceCodeStore {
    /** Entry count, for tests and for the sweep's own coverage. */
    size(): number;
    /** Stop the sweep timer. */
    dispose(): void;
}
export declare const createMemoryDeviceCodeStore: (options?: MemoryDeviceCodeStoreOptions) => MemoryDeviceCodeStore;
//# sourceMappingURL=memory.d.mts.map