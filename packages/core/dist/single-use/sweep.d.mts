/**
 * When the in-process challenge store and replay seen-set sweep their expired
 * entries: once `sweepInterval` writes have accumulated **and** at least
 * `minSweepIntervalMs` has passed since the last sweep.
 *
 * Both stores are keyed by values that are never presented again once they
 * are done with — a finished or abandoned ceremony's challenge, an honoured
 * assertion's `jti` — so reclaiming an entry only when it is looked up again
 * reclaims almost nothing, and the sweep has to be its own step. It is
 * amortized on the store's writes rather than run on a timer: a background
 * interval would need lifecycle registration to avoid holding the process
 * open, and a write is the only operation that grows the map. The count
 * bounds the work per write; the floor bounds the O(size) scans per second
 * whatever the write rate. The floor is measured on the monotonic clock
 * (`performance.now()`), so a wall clock stepped back cannot stall sweeps;
 * which entries are expired stays the store's call, on the wall clock their
 * expiries are written in. Writes keep counting through the floor, so the
 * first write after it sweeps.
 *
 * The result is bounded growth, not zero-lag reclamation: the resident set is
 * the live entries plus at most those that expired within one interval.
 */
/**
 * How a store's sweep is paced; each value left out (`undefined`) takes the
 * store's default.
 * A value given that cannot be used is a `RangeError` naming the store and
 * the option — never replaced by the default, which would leave a setting
 * that says one thing and a store that does another.
 */
export interface AmortizedSweepOptions {
    /** Writes between sweeps: a positive whole number. */
    readonly sweepInterval?: number;
    /**
     * The least time between two sweeps: a whole number of milliseconds, `0`
     * or more. `0` sweeps on the write interval alone.
     */
    readonly minSweepIntervalMs?: number;
}
export interface AmortizedSweep {
    /** Count one write; `true` when the caller is to sweep now. */
    wrote(): boolean;
    /**
     * `true` when the caller may sweep now whatever the write count — at
     * least `minSweepIntervalMs` since the last sweep — and counts it as that
     * sweep. For a store at its cap, which reclaims what has expired before it
     * refuses: a sweep per refused write would make each one O(size) under
     * the flood that fills it.
     */
    due(): boolean;
}
/**
 * The pacing for a store: `owner` names it (the factory the options were
 * given to) in the refusal of an option it cannot use.
 */
export declare function createAmortizedSweep(options: AmortizedSweepOptions, defaults: {
    readonly sweepInterval: number;
    readonly minSweepIntervalMs: number;
}, owner: string): AmortizedSweep;
//# sourceMappingURL=sweep.d.mts.map