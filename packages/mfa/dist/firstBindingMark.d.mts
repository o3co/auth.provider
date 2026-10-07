/**
 * The settings a mark is read from: `mfa.manage.maxAgeSeconds`,
 * `mfa.transactionTtlSeconds` and `mfa.storeTimeoutMs`, whose factor-set
 * lease (`leaseMsFor`) is the one the factor set's writes take.
 */
export interface FirstBindingMarkSettings {
    readonly manageMaxAgeSeconds: number;
    readonly transactionTtlSeconds: number;
    readonly storeTimeoutMs: number;
}
/** How long a mark noted now stands, in whole milliseconds (see this file's header). */
export declare function firstBindingMarkLifetimeMs(settings: FirstBindingMarkSettings): number;
/**
 * What `firstBindingAt(subject, nowMs)` answered, read through core's
 * `readFirstBindingAt`: the mark's time, or `null` for none. Throws a
 * `TypeError` for anything else.
 */
export declare function readFirstBindingMark(answer: unknown, nowMs: number): number | null;
/** One subject's first-binding mark as every reader judges it, over the settings it was built with. */
export interface FirstBindingMark {
    /** How long a mark noted now stands, in whole milliseconds. */
    readonly lifetimeMs: number;
    /**
     * How long after a read finds no mark that read still covers a binding: a
     * mark noted since stands its lifetime, less the skew and the lease it may
     * be noted ahead of its write.
     */
    readonly readCoversMs: number;
    /**
     * Whether a mark at `markAtMs` distrusts an authentication at
     * `authTimeMs`: one not later than the mark by more than
     * `DEFAULT_CLOCK_SKEW_MS` and one lease, or one that is not a number.
     * None, with no mark.
     */
    distrusts(authTimeMs: number | undefined, markAtMs: number | null): boolean;
    /**
     * How long from `nowMs` until an authentication is no longer distrusted by
     * a mark at `markAtMs`, on this clock. Another replica's clock may put it
     * up to the skew later.
     */
    retryAfterMs(markAtMs: number, nowMs: number): number;
}
/** The mark over `settings` (see this file's header); a setting out of its range is a `RangeError` naming it. */
export declare function createFirstBindingMark(settings: FirstBindingMarkSettings): FirstBindingMark;
//# sourceMappingURL=firstBindingMark.d.mts.map