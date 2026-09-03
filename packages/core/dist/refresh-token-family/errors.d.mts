/**
 * Reasons emitted by `RefreshTokenStorageError`.
 *
 * - `duplicate-family`: registerFamily called for an existing familyId
 *   (RNG collision or programming bug; surfaces loudly).
 * - `expired-at-issue`: register/issue path detected `expiresAt <= now()`
 *   at call time; the storage layer fails closed.
 * - `conflict-exhausted`: updateFamily's CAS retry budget exhausted under
 *   sustained contention; load-shedding signal.
 *
 * Per A3 §5.4.
 */
export type RefreshTokenStorageErrorReason = "duplicate-family" | "expired-at-issue" | "conflict-exhausted";
/**
 * Single error class for `RefreshTokenFamilyStore` domain failures.
 * Mirrors A1's `ChallengeStorageError` shape: discriminated `reason` field,
 * native ES2022 `cause` for chaining underlying adapter errors, default
 * message templated from `reason`.
 *
 * Per A3 §5.4.
 */
export declare class RefreshTokenStorageError extends Error {
    readonly reason: RefreshTokenStorageErrorReason;
    constructor(opts: {
        reason: RefreshTokenStorageErrorReason;
        message?: string;
        cause?: unknown;
    });
}
//# sourceMappingURL=errors.d.mts.map