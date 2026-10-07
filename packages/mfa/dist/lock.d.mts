/**
 * The subject lock in the verify path (the MFA ADR's D21, F1 step 5), over
 * the transaction store's lock operations and `mfa.lockout`.
 *
 * - A guessable proof reserves one of its subject's attempts before it is
 *   checked, and settles it once. Only a factor that says it is not
 *   guessable is exempt: it reserves nothing, passes during every hold, and
 *   records an exempt success when it settles a success, which ends a run
 *   before the hard hold is fixed and never the hard hold (the store's rule,
 *   handed the policy). Each is judged at
 *   the time its verification passes, so one verification has one time.
 * - A refusal names its hold, when an attempt may come back (none for the
 *   hard hold), and whether it begins an episode.
 * - A reservation the store cannot answer, or answers outside the port
 *   (core's `readMfaSubjectAttemptReservation`), is an outage: never a pass,
 *   never a hold.
 * - Settling never throws: a settle or an exempt success the store does not
 *   take is handed to `unsettled` once, and the answer stands. The attempt
 *   it leaves pending counts as a failure.
 */
import { type MfaFactor, type MfaFactorRecord, type MfaFactorResolver, type MfaLockoutPolicy, type MfaSubjectAttemptOutcome, type MfaSubjectHold, type MfaTransactionStore } from "@o3co/auth-provider-core";
import { type MfaStoreOutage } from "./ceremony.mjs";
/** An attempt let through: settle it once, `failure`, `success` or `void`. */
export interface MfaSubjectLockEntry {
    readonly outcome: "entered";
    settle(outcome: MfaSubjectAttemptOutcome): Promise<void>;
}
/** A guessable attempt the subject's hold refused. */
export interface MfaSubjectLocked {
    readonly outcome: "locked";
    readonly hold: MfaSubjectHold;
    /** Milliseconds until an attempt may be reserved; `null` for the hard hold. */
    readonly retryAfterMs: number | null;
    /** Whether this refusal begins an episode. */
    readonly first: boolean;
}
/** A settle or an exempt success the store did not take. */
export interface MfaSubjectLockUnsettled {
    readonly subject: string;
    readonly kind: string;
    readonly step: "settleSubjectAttempt" | "noteExemptSuccess";
    readonly outcome: MfaSubjectAttemptOutcome;
    readonly cause: unknown;
}
export interface MfaSubjectLock {
    /**
     * An attempt of `subject` with a proof of `factor`'s at `nowMs`, the
     * verification's time: let through, refused by a hold, or the store's
     * outage. An exempt success it settles is dated `nowMs`.
     */
    enter(subject: string, factor: Pick<MfaFactor, "kind" | "guessable">, nowMs: number): Promise<MfaSubjectLockEntry | MfaSubjectLocked | MfaStoreOutage>;
}
export interface MfaSubjectLockOptions {
    readonly store: Pick<MfaTransactionStore, "reserveSubjectAttempt" | "settleSubjectAttempt" | "noteExemptSuccess">;
    /** `mfa.lockout`. */
    readonly policy: MfaLockoutPolicy;
    readonly unsettled: (failure: MfaSubjectLockUnsettled) => void;
}
/** The subject lock over `options` (see this file's header). */
export declare function createMfaSubjectLock(options: MfaSubjectLockOptions): MfaSubjectLock;
/**
 * The exempt kinds `subject` holds — installed, not guessable, with at
 * least one record — each once, in code-unit order. An inventory, not a
 * verdict: whether one works shows at its verification.
 */
export declare function exemptKindsHeld(options: {
    readonly records: readonly MfaFactorRecord[];
    readonly factors: MfaFactorResolver;
}): string[];
//# sourceMappingURL=lock.d.mts.map