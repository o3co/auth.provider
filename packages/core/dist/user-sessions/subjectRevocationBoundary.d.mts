import type { SubjectRevocation } from "./types.mjs";
/**
 * `value`'s epoch milliseconds when it is a `Date` (of any realm) with a
 * finite time; else a `RangeError` naming `name`. An object that only answers
 * `getTime` is not a date: its time could read back as no instant at all.
 */
export declare function checkSubjectRevocationInstant(value: unknown, name: string): number;
/**
 * `storeNowMs` when it is an instant a `Date` can hold; else a `RangeError`.
 * A store whose clock is read in-process reads it through this before it
 * compares or drops a record, so a reading of no instant fails the operation
 * and lapses nothing.
 */
export declare function checkSubjectRevocationClock(storeNowMs: unknown): number;
/**
 * The rule every store bounds a boundary by: `before` when it is no later
 * than `storeNowMs + DEFAULT_CLOCK_SKEW_MS`, else exactly that, with `clamped`
 * saying which. A `RangeError` for a `before` that is no date, or a clock
 * whose reading or bound a `Date` cannot hold: the bound is never skipped,
 * and never answers an Invalid Date. A store whose
 * clock is read in-process calls it in the step that writes; a store whose
 * clock is a server's clamps in its own atomic step there, and may call it
 * with the `now` that server answers to tell whether it clamped.
 */
export declare function clampSubjectRevocationBoundary(before: unknown, storeNowMs: number): {
    readonly boundary: Date;
    readonly clamped: boolean;
};
/**
 * What {@link subjectBoundaryCovers} found: the subject's boundary covers the
 * claim (refuse), does not (go on), or could not be read or compared
 * (`cause`; answer it as an outage, never as either verdict).
 */
export type SubjectBoundaryAnswer = {
    readonly answer: "covered";
} | {
    readonly answer: "clear";
} | {
    readonly answer: "unavailable";
    readonly cause: unknown;
};
/**
 * Whether `subject`'s sessions boundary covers a claim in NumericDate seconds
 * (an assertion's or a proof's issue time), for a grant that compares before
 * it signs. One read of the boundary, compared by the rule and allowance
 * `verifyJwt` applies to `iat` (`claimCoveredByRevocationBoundary`,
 * `DEFAULT_SUBJECT_REVOCATION_SKEW_MS`).
 *
 * - No boundary in force: `clear`, whatever the claim.
 * - A boundary in force and a claim that is absent or not a finite number:
 *   `covered`, as `verifyJwt` refuses a token without `iat`: it cannot show
 *   it postdates the boundary.
 * - A read that throws, or a boundary that is not a `Date` with a finite
 *   time: `unavailable`, whatever the claim.
 *
 * Call it as the last read before signing, after the issuance instant is
 * fixed, so a revocation stamped while earlier steps ran is seen.
 */
export declare function subjectBoundaryCovers(subjectRevocation: Pick<SubjectRevocation, "revokedBefore">, subject: string, claimSeconds: number | undefined): Promise<SubjectBoundaryAnswer>;
//# sourceMappingURL=subjectRevocationBoundary.d.mts.map