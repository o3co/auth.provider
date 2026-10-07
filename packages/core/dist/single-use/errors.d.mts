/**
 * Discriminated reason union for ChallengeStorageError.
 * Per A1 §5.4 (lines 224-243).
 */
export type ChallengeStorageErrorReason = "duplicate" | "expired-at-issue";
/**
 * Single discriminated-reason error class for ChallengeStore + ReplaySeenSet
 * adapter primitives. Mirrors AdapterFactoryError / BootError discipline
 * (one class, discriminated reason, no per-reason subclasses).
 *
 * Per A1 §5.4. Throw matrix (A1 §5.4 lines 250-258):
 *   ChallengeStore.issue       — "duplicate" | "expired-at-issue"
 *   ChallengeStore.find        — (no throws)
 *   ChallengeStore.consume     — (no throws)
 *   ReplaySeenSet.markSeen     — "expired-at-issue"
 *   ReplaySeenSet.contains     — (no throws)
 *   ChallengeCeremony.consume  — (no throws in normal flow)
 *
 * An expiry outside the Date range (NaN, ±Infinity, past ±8.64e15 ms)
 * passed to `issue` or `markSeen` is a RangeError, not
 * this class: it is a caller fault rather than a storage outcome, and must
 * not be mistaken for the `expired-at-issue` race the ceremony swallows.
 */
export declare class ChallengeStorageError extends Error {
    readonly reason: ChallengeStorageErrorReason;
    constructor(opts: {
        reason: ChallengeStorageErrorReason;
        message?: string;
        cause?: unknown;
    });
}
//# sourceMappingURL=errors.d.mts.map