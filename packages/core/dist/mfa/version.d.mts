/**
 * The one bound on an MFA record's version (the MFA ADR's D7, D8): the
 * compare-and-set token both stores, `MfaFactorStore` and
 * `MfaTransactionStore`, bump by one on every update. A record may be created
 * at any safe non-negative version, and the update from
 * `Number.MAX_SAFE_INTEGER` is the one that cannot advance: its next version
 * is no safe integer — a store would write 2^53, which a read refuses, or
 * keep a version that no longer moves, so two writers would both win.
 */
/**
 * Refuses, with a `RangeError` naming `operation`, an update at
 * `expectedVersion` whose next version would not be a safe integer —
 * `Number.MAX_SAFE_INTEGER` — before anything is read or written, whatever
 * the stored version, as a value a field does not admit is refused. Every
 * other value passes: one no record can be at is the store's `null`.
 */
export declare function checkMfaVersionAdvances(expectedVersion: number, operation: string): void;
//# sourceMappingURL=version.d.mts.map