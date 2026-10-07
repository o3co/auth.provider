/**
 * The MFA transaction, the subject lock state that bounds guessable proofs and
 * its authorized recovery, a subject's generation, lease and recovery-set
 * floor, a session's account-email proof, a subject's first-binding mark, the
 * port that keeps them, and its `mfaTransactionStore` slot. See ADR 2026-09-25-multi-factor-authentication
 * (the MFA transaction; attempts, lockout and rate limits; D24).
 *
 * A transaction is the short-lived, single-use record of one second-factor
 * ceremony, bound to what started it. Every operation a race could split is
 * atomic in the store: attempts are reserved before a proof is checked, a
 * challenge is taken once, and one verification in flight consumes it.
 *
 * Subject state is judged on the time each caller passes, not the store's
 * clock, so callers' clocks must agree (NTP); see
 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} for what a fast clock can erase. A
 * subject's run never expires (only a success, an exempt success before the
 * hard hold or an applied recovery ends it), nor does the hard hold (only
 * an applied recovery lifts it), and an open sign-up lets anyone mint
 * subjects.
 *
 * Every mechanism a subject's factor-set writes rely on is state of this
 * store, judged in its atomic operations: a writer captures the subject's
 * generation, writes under the subject's lease acquired at that generation,
 * and the generation moves only under the lease, at an applied recovery or
 * reset. The lease is logical: a write that outlives it is told so at its
 * release, never stopped.
 *
 * Transactions are bounded by their expiry, and per binding: a binding holds
 * at most {@link MFA_MAX_TRANSACTIONS_PER_BINDING} live transactions, and
 * opening one more ends its oldest. This manages the state the store owns;
 * it is no abuse defence, and nothing caps transactions per subject.
 */
import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { PrimaryContinuation } from "../session-admission/requirement.mjs";
/**
 * A transaction bound to a browser session: `id` is the express session id the
 * login route regenerated, or the one a step-up or an enrollment began in.
 */
export interface MfaSessionBinding {
    readonly kind: "session";
    readonly id: string;
}
/**
 * What a transaction is bound to: the one party that may continue its ceremony.
 * Discriminated by `kind` (a browser session today; a browserless transport
 * adds its own kinds). A store keeps it whole, as data, reading neither field.
 * Every use compares the whole binding, kind included
 * ({@link isMfaTransactionBoundTo}), so another kind never matches, even with
 * the same id.
 */
export type MfaTransactionBinding = MfaSessionBinding;
/** One second-factor ceremony. Every field is a required key: a store that drops one does not compile. */
export interface MfaTransaction {
    /** 32 bytes from the CSPRNG, base64url. Never in a URL. */
    readonly id: string;
    readonly purpose: "login" | "step_up" | "enroll";
    /** What it is bound to; every use compares the whole binding, kind included, with the request's. */
    readonly binding: MfaTransactionBinding;
    readonly subject: string;
    /** `step_up` / `enroll`: the `UserSession` it upgrades. */
    readonly sid: string | undefined;
    /**
     * `login`: the continuation `admitPrimary` answered (the primary, the `User`
     * the session will be built from, and what earlier requirements added),
     * presented to `resumePrimary` when the ceremony completes.
     */
    readonly continuation: PrimaryContinuation | undefined;
    /** `login`: where the page goes afterwards, already held to `session.redirectAllowlist`. */
    readonly redirectTo: string | undefined;
    readonly enrollment: "none" | "allowed" | "required";
    readonly emailProof: "not_required" | "required" | {
        readonly provedAtMs: number;
    };
    /** `step_up`: the `acr_values` hinted, for offering factors. */
    readonly acrValues: readonly string[] | undefined;
    /** A challenge sent and not yet taken; `state` sealed or digested. */
    readonly challenge: {
        readonly factorId: string;
        readonly kind: string;
        readonly state: string;
        readonly expiresAtMs: number;
    } | undefined;
    /** An enrollment begun and not yet completed; `state` sealed. */
    readonly pendingEnrollment: {
        readonly kind: string;
        readonly state: string;
        readonly expiresAtMs: number;
    } | undefined;
    /** Attempts reserved: only `reserveAttempt` moves it. */
    readonly attempts: number;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
    /** The compare-and-set token: `update` alone moves it. */
    readonly version: number;
}
/**
 * What `update` may change. A value sets the field; `null` clears a clearable
 * field (`challenge`, `pendingEnrollment`). An absent or `undefined` key leaves
 * the field alone, so a patch never clears a requirement by omission. A value
 * the field does not admit, or `null` for an unclearable field, is a
 * `RangeError` ({@link mfaTransactionPatchWrites}). Other keys are ignored.
 */
export interface MfaTransactionPatch {
    readonly enrollment?: MfaTransaction["enrollment"];
    readonly emailProof?: MfaTransaction["emailProof"];
    readonly challenge?: NonNullable<MfaTransaction["challenge"]> | null;
    readonly pendingEnrollment?: NonNullable<MfaTransaction["pendingEnrollment"]> | null;
}
/** The keys an {@link MfaTransactionPatch} may carry, for an adapter that copies one field by field. */
export declare const MFA_TRANSACTION_PATCH_KEYS: readonly ["enrollment", "emailProof", "challenge", "pendingEnrollment"];
/**
 * What a patch writes, per {@link MfaTransactionPatch}: each key with its value
 * as the store keeps it (sub-objects copied to known fields), or `undefined`
 * for a field `null` clears. Absent, `undefined` and unknown keys are skipped.
 * Throws a `RangeError` naming the key before anything is written. Every
 * adapter calls it first, then {@link checkMfaTransactionTransitions} on the
 * record at the expected version.
 */
export declare function mfaTransactionPatchWrites(patch: MfaTransactionPatch): readonly (readonly [keyof MfaTransactionPatch, unknown])[];
/**
 * Refuses, with a `RangeError`, writes that would undo a requirement of
 * `current`: a required email proof becoming anything but met or a met one
 * undone (a required proof is met, never waived), `enrollment` lowered
 * (`none` < `allowed` < `required`). Every adapter calls it on the record at
 * the expected version, before writing.
 */
export declare function checkMfaTransactionTransitions(current: MfaTransaction, writes: readonly (readonly [keyof MfaTransactionPatch, unknown])[]): void;
/**
 * The record a store keeps for a new transaction, or a `RangeError`. Every
 * field is held to its type (patch fields by the patch rules, `enrollment` and
 * `emailProof` required), `attempts` must be `0`, and `version` a safe
 * non-negative integer: a limit is only as good as the count it starts from
 * (with `attempts` NaN, `NaN + 1 > max` is false and every reservation
 * passes). Only a transaction's fields are kept, sub-objects copied to known
 * fields. Every adapter calls it in `create`, beside its own expiry check.
 */
export declare function newMfaTransactionRecord(tx: MfaTransaction): MfaTransaction;
/**
 * The most live transactions one binding holds — a browser session's tabs,
 * each in a ceremony of its own. `create` past it ends the binding's oldest
 * rather than refusing the new one: the transaction a user opened last is the
 * one they are looking at. A core constant, not configuration: it bounds the
 * state the store owns, which no deployment needs to raise.
 */
export declare const MFA_MAX_TRANSACTIONS_PER_BINDING = 5;
/**
 * Whether `tx` is bound to `binding`, the whole binding compared, kind
 * included. Another kind, a binding either side does not admit (such as an id
 * that is not a well-formed string), or one whose reading throws never matches.
 * Each side is read once and the ids compared in constant time. Every use of a
 * transaction makes this comparison, through {@link getBoundMfaTransaction}.
 *
 * Constant time holds only for ids of equal length (`security/timingSafe.mts`).
 * The session kind's length is public (an express session id is 32 characters,
 * carried in the cookie); a kind with secret-length ids must compare
 * fixed-length digests instead.
 */
export declare function isMfaTransactionBoundTo(tx: Pick<MfaTransaction, "binding">, binding: MfaTransactionBinding): boolean;
/**
 * The transaction `id` names if it is bound to `binding`
 * ({@link isMfaTransactionBoundTo}), else `null`: a transaction bound to
 * anything else reads as an unknown id, so a mismatch reveals nothing. A store
 * that cannot answer rejects, as its `get` does.
 *
 * - **It comes first.** Every use of a transaction starts with this read, then
 *   calls only operations carrying the version it read (`update`,
 *   `takeChallenge`, `consume`), plus `reserveAttempt` once the read held: that
 *   deletes the transaction past `max`, so on a bare id anyone holding it could
 *   destroy the ceremony.
 * - **It is necessary, not sufficient.** A `step_up` or `enroll` transaction
 *   upgrades one `UserSession`; the route also compares `tx.sid` with the
 *   session's `sid`.
 */
export declare function getBoundMfaTransaction(store: Pick<MfaTransactionStore, "get">, id: string, binding: MfaTransactionBinding): Promise<MfaTransaction | null>;
/**
 * `answer`, what `reserveAttempt(id, max)` answered, as the port promises
 * it: `ok` the literal boolean, `attempts` a safe integer — from 1 to `max`
 * when reserved, from 0 when not. `undefined` for anything else, which the
 * caller answers as the store's outage before any proof is checked: a count
 * it cannot read limits nothing. Each field is read once.
 */
export declare function readMfaAttemptReservation(answer: unknown, max: number): {
    readonly ok: boolean;
    readonly attempts: number;
} | undefined;
/**
 * `answer`, what `reserveSubjectAttempt` answered, as the port promises it:
 * a pass with its reservation, a non-empty string; or a hold the port names,
 * with `first` a boolean and a time to come back — `null` for the hard hold,
 * else a finite number of milliseconds above 0, since the hold applies at the
 * time asked about. Copied to those fields. `undefined` for anything else,
 * which the caller answers as the store's outage: never a pass, never a hold.
 * Each field is read once.
 */
export declare function readMfaSubjectAttemptReservation(answer: unknown): MfaSubjectAttemptReservation | undefined;
/**
 * `answer`, what `sessionEmailProofAt(subject, sid, nowMs)` answered, as the
 * port promises it: `null` for no proof, or when the proof was given — a
 * finite instant from the epoch to `nowMs`. `undefined` for anything else,
 * which the caller answers as the store's outage: a proof it cannot read
 * admits nothing.
 */
export declare function readSessionEmailProof(answer: unknown, nowMs: number): number | null | undefined;
/** A session's account-email proof as a store keeps it. */
export interface SessionEmailProof {
    readonly provedAtMs: number;
    readonly untilMs: number;
}
/**
 * Refuses, with a `RangeError` naming what is wrong, a session's
 * account-email proof a store cannot keep, on `storeNowMs`, its clock:
 * `subject` and `sid` non-empty strings; `provedAtMs` and `untilMs` epoch
 * milliseconds, `untilMs` after `provedAtMs` and after `storeNowMs`, within
 * the Date range; `provedAtMs` no further ahead of `storeNowMs` than
 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS}. Every adapter runs it before it
 * records a proof, and on one it reads back.
 */
export declare function checkSessionEmailProof(subject: unknown, sid: unknown, provedAtMs: unknown, untilMs: unknown, storeNowMs: number): void;
/**
 * What a store answers of `proof` asked about at `nowMs`, on `storeNowMs`,
 * its clock: when it was given, no later than `nowMs`, while its `untilMs`
 * is after both; else `null`. Every adapter answers through it.
 */
export declare function sessionEmailProofAnswer(proof: SessionEmailProof, nowMs: number, storeNowMs: number): number | null;
/**
 * Refuses, with a `RangeError`, a question `sessionEmailProofAt` cannot
 * answer: `subject` and `sid` non-empty strings, `nowMs` an instant from the
 * epoch within the Date range. Every adapter runs it first.
 */
export declare function checkSessionEmailProofQuestion(subject: unknown, sid: unknown, nowMs: unknown): void;
/**
 * `answer`, what `firstBindingAt(subject, nowMs)` answered, as the port
 * promises it: `null` for no mark, or when it was noted — whole epoch
 * milliseconds, no further ahead of `nowMs` than `DEFAULT_CLOCK_SKEW_MS`.
 * `undefined` for anything else, which the caller answers as the store's
 * outage: a mark it cannot read trusts no session. This is the mark's one
 * reading.
 */
export declare function readFirstBindingAt(answer: unknown, nowMs: number): number | null | undefined;
/** A subject's first-binding mark as a store keeps it. */
export interface FirstBindingMark {
    readonly atMs: number;
    readonly untilMs: number;
}
/**
 * Refuses, with a `RangeError` naming what is wrong, a first-binding mark a
 * store cannot keep. Its shape: `subject` a non-empty string; `atMs` and
 * `untilMs` whole epoch milliseconds within the Date range, `untilMs` after
 * `atMs` by at most {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} (a mark stands a day
 * at most). On `storeNowMs`, the store's clock, when it is given: `untilMs`
 * after it, and `atMs` no further from it, either way, than
 * `DEFAULT_CLOCK_SKEW_MS`. Every adapter runs it before it notes a mark; an
 * adapter whose store judges the clock in a script runs the shape first and
 * the rest on the clock that script answers. A mark read back is held to the
 * shape, as an outage; where its time sits on the clock is the caller's
 * reading ({@link readFirstBindingAt}) to judge.
 */
export declare function checkFirstBindingNote(subject: unknown, atMs: unknown, untilMs: unknown, storeNowMs?: number): void;
/**
 * Refuses, with a `RangeError`, a question `firstBindingAt` cannot answer:
 * `subject` a non-empty string, `nowMs` an instant from the epoch within the
 * Date range. Every adapter runs it first.
 */
export declare function checkFirstBindingQuestion(subject: unknown, nowMs: unknown): void;
/**
 * The mark a store keeps of `held`, a mark that still stands on its clock,
 * and `next`: the later `atMs` and the later `untilMs`, whichever mark each
 * comes from. A mark distrusts, so no note moves it back or shortens it.
 */
export declare function laterFirstBindingMark(held: FirstBindingMark, next: FirstBindingMark): FirstBindingMark;
/**
 * What a store answers of `mark` on `storeNowMs`, its clock: `atMs`, never
 * moved earlier, while `untilMs` is after it; else `null`. The caller's time
 * never ends a mark. Every adapter answers through it.
 */
export declare function firstBindingAnswer(mark: FirstBindingMark, storeNowMs: number): number | null;
/**
 * Whether `consumed`, what `consume(bound.id, bound.version)` answered other
 * than `null`, is the transaction the bound read returned: the same id,
 * version, purpose, subject and `redirectTo`, bound to the same binding, and
 * a continuation — when the read had one — for the same subject and
 * redirect. The caller answers anything else as the store's outage and writes
 * nothing, before a factor moves on or a login resumes.
 */
export declare function isConsumedMfaTransaction(consumed: unknown, bound: MfaTransaction): consumed is MfaTransaction;
/**
 * The subject lock policy (`mfa.lockout`). Every field is a positive whole
 * number; {@link checkMfaLockoutPolicy} is the rule.
 */
export interface MfaLockoutPolicy {
    /** Consecutive failures that start the short backoff (5); at most `hardLimit`. */
    readonly threshold: number;
    /** The first backoff lock, in seconds (900); each further failure doubles it. */
    readonly baseSeconds: number;
    /**
     * The longest backoff lock, in seconds (86400); a configured policy, at
     * most {@link MFA_LOCKOUT_MAX_BACKOFF_SECONDS}.
     */
    readonly maxSeconds: number;
    /**
     * How long after the last lock ends the backoff is forgotten, in seconds
     * (86400). Before any lock, the same quiet period after the previous failure
     * restarts the count. Neither ends the run the hard limit counts.
     */
    readonly memorySeconds: number;
    /** Failures allowed in any rolling seven days (10). */
    readonly weeklyBudget: number;
    /**
     * Consecutive attempts (100), reservations in flight counted, at which
     * guessable proofs are held until the subject's lock state is cleared
     * (`applySubjectRecovery`): the attempt that is the hardLimit-th since the
     * last success holds, whatever its outcome. This is one stricter than
     * NIST's '100 failed attempts': a correct hardLimit-th attempt still signs
     * in, but guessable factors stay held until re-enrolled. The hold is fixed
     * when the run reaches it: no time, no settle, no exempt success and no
     * higher `hardLimit` lifts it. NIST SP 800-63B-4's cap on consecutive
     * failed attempts is per authenticator and a ceiling; the per-subject
     * latch, and holding at the hardLimit-th attempt whatever its outcome, are
     * this product's choice. At most {@link MFA_LOCKOUT_MAX_HARD_LIMIT}; a
     * configured policy, at least {@link MFA_LOCKOUT_MIN_HARD_LIMIT} and above
     * `threshold` ({@link checkConfiguredMfaLockoutPolicy}).
     */
    readonly hardLimit: number;
}
/** The weekly budget's window: any rolling seven days. */
export declare const MFA_WEEKLY_WINDOW_MS: number;
/**
 * How long a store keeps a failure after it stops counting: a day, on the
 * store's clock. A caller whose clock runs ahead by less erases nothing
 * a caller on time still counts. With NTP-synced clocks a day is ample; it
 * costs a day of extra state.
 */
export declare const MFA_CLOCK_SKEW_ALLOWANCE_MS = 86400000;
/** The most consecutive failures a lockout policy may allow: NIST SP 800-63B-4's cap. */
export declare const MFA_LOCKOUT_MAX_HARD_LIMIT = 100;
/**
 * The smallest `hardLimit` a configured policy may set
 * ({@link checkConfiguredMfaLockoutPolicy}).
 */
export declare const MFA_LOCKOUT_MIN_HARD_LIMIT = 10;
/**
 * The longest `maxSeconds` a configured policy may set, a week
 * ({@link checkConfiguredMfaLockoutPolicy}).
 */
export declare const MFA_LOCKOUT_MAX_BACKOFF_SECONDS: number;
/**
 * Which hold refused a guessable attempt. Once fixed, no time, no settle, no
 * exempt success and no higher `hardLimit` lifts `hard`; an applied recovery
 * does (`applySubjectRecovery`).
 */
export type MfaSubjectHold = "backoff" | "weekly" | "hard";
/** What `reserveSubjectAttempt` answers. */
export type MfaSubjectAttemptReservation = {
    readonly ok: true;
    /** The attempt's handle for `settleSubjectAttempt`: a non-empty string. */
    readonly reservation: string;
} | {
    readonly ok: false;
    readonly hold: MfaSubjectHold;
    /**
     * Milliseconds from the time asked about until an attempt may be
     * reserved; above 0 for a backoff or weekly hold, `null` for the hard hold.
     */
    readonly retryAfterMs: number | null;
    /**
     * Whether this refusal begins an episode: the refusals from the first
     * after an attempt was let through, or after an applied recovery, to
     * the next attempt let through. One refusal among any in flight is first.
     */
    readonly first: boolean;
};
/**
 * How a reserved attempt ended. `failure`: it stands. `success`: a guessable
 * proof verified; it ends the consecutive run up to and including this
 * reservation (a later one still in flight starts the next). `void`: the proof
 * was right but the factor's write lost or failed; the attempt is removed and
 * the run goes on. Neither lifts a hard hold already fixed.
 */
export type MfaSubjectAttemptOutcome = "failure" | "success" | "void";
/** The shortest subject lease a store gives. */
export declare const MFA_SUBJECT_LEASE_MIN_MS = 1000;
/** The longest subject lease a store gives. */
export declare const MFA_SUBJECT_LEASE_MAX_MS = 600000;
/**
 * The lease a factor-set write takes when its configuration names none: above
 * the few Store calls one write makes at the Store transport's default timeout.
 */
export declare const DEFAULT_MFA_SUBJECT_LEASE_MS = 60000;
/** What a subject lease is asked for with. */
export interface MfaSubjectLeaseRequest {
    /** How long it stands on the store's clock, from {@link MFA_SUBJECT_LEASE_MIN_MS} to {@link MFA_SUBJECT_LEASE_MAX_MS}. */
    readonly ttlMs: number;
    /** The subject's generation the writer captured before it began. */
    readonly generation: number;
}
/** What `acquireSubjectLease` answers. */
export type MfaSubjectLeaseAnswer = {
    readonly outcome: "acquired";
    /** What `releaseSubjectLease` and `applySubjectRecovery` are handed: a non-empty string. */
    readonly token: string;
} | {
    readonly outcome: "busy";
    /** Milliseconds until another holder's lease ends, above 0. */
    readonly retryAfterMs: number;
} | {
    readonly outcome: "stale";
};
/**
 * The request {@link MfaTransactionStore.acquireSubjectLease} acts on, its
 * fields read once, or a `RangeError`: `subject` a non-empty string, `ttlMs`
 * a whole number from {@link MFA_SUBJECT_LEASE_MIN_MS} to
 * {@link MFA_SUBJECT_LEASE_MAX_MS}, `generation` a safe whole number from 0.
 * Every adapter calls it first.
 */
export declare function checkSubjectLeaseRequest(subject: unknown, request: unknown): MfaSubjectLeaseRequest;
/**
 * Refuses, with a `RangeError` naming `operation`, a subject that is not a
 * non-empty string. Every adapter runs it first for the operations that take
 * a subject alone.
 */
export declare function checkSubjectQuestion(operation: string, subject: unknown): void;
/**
 * Refuses, with a `RangeError`, a release `releaseSubjectLease` cannot make:
 * `subject` and `token` non-empty strings. Every adapter runs it first.
 */
export declare function checkSubjectLeaseRelease(subject: unknown, token: unknown): void;
/**
 * `answer`, what `acquireSubjectLease` answered, as the port promises it,
 * copied to its outcome's fields, each read once; `undefined` for anything
 * else, which the caller answers as the store's outage: never a lease, never
 * a refusal.
 */
export declare function readMfaSubjectLeaseAnswer(answer: unknown): MfaSubjectLeaseAnswer | undefined;
/**
 * `answer`, a subject's generation or recovery-set floor as the port promises
 * it: a safe whole number from 0. `undefined` for anything else, which the
 * caller answers as the store's outage.
 */
export declare function readMfaSubjectCount(answer: unknown): number | undefined;
/** What `raiseRecoverySetFloor` is asked to raise, and under which lease. */
export interface MfaRecoverySetFloorRaise {
    /** A recovery-code set's generation, not the subject's: a safe whole number from 1. */
    readonly setGeneration: number;
    /** The subject's lease the caller holds. */
    readonly leaseToken: string;
}
/** What `raiseRecoverySetFloor` answers: the floor after the raise, or the refusal without the lease. */
export type MfaRecoverySetFloorAnswer = {
    readonly outcome: "raised";
    readonly floor: number;
} | {
    readonly outcome: "refused";
    readonly reason: "lease_not_held";
};
/**
 * The raise `raiseRecoverySetFloor` makes, its fields read once, or a
 * `RangeError`: `subject` a non-empty string, `setGeneration` a safe whole
 * number from 1, `leaseToken` a non-empty string. Every adapter calls it
 * first.
 */
export declare function checkRecoverySetFloorRaise(subject: unknown, raise: unknown): MfaRecoverySetFloorRaise;
/**
 * `answer`, what `raiseRecoverySetFloor` answered, as the port promises it:
 * a raise with the floor after it, a safe whole number from 1, or the
 * refusal without the lease. `undefined` for anything else, which the caller
 * answers as the store's outage.
 */
export declare function readMfaRecoverySetFloorAnswer(answer: unknown): MfaRecoverySetFloorAnswer | undefined;
/** Under which lease `consumeEmailProofRequirement` consumes the email-proof requirement. */
export interface MfaEmailProofRequirementConsume {
    /** The subject's lease the caller holds. */
    readonly leaseToken: string;
}
/**
 * What `consumeEmailProofRequirement` answers under a lease: `consumed` for
 * the one caller that cleared the requirement, `absent` when none stood, or
 * the refusal without the lease, nothing cleared.
 */
export type MfaEmailProofRequirementConsumeAnswer = {
    readonly outcome: "consumed";
} | {
    readonly outcome: "absent";
} | {
    readonly outcome: "refused";
    readonly reason: "lease_not_held";
};
/**
 * The consume `consumeEmailProofRequirement` makes under a lease, its field
 * read once, or a `RangeError`: `subject` and `leaseToken` non-empty strings.
 * Every adapter calls it first.
 */
export declare function checkEmailProofRequirementConsume(subject: unknown, consume: unknown): MfaEmailProofRequirementConsume;
/**
 * `answer`, what `consumeEmailProofRequirement` answered under a lease, as
 * the port promises it. `undefined` for anything else, which the caller
 * answers as the store's outage.
 */
export declare function readMfaEmailProofRequirementConsumeAnswer(answer: unknown): MfaEmailProofRequirementConsumeAnswer | undefined;
/** The two authorized recoveries: `recover`, the subject's own after an exempt proof; `reset`, the operator's. */
export type MfaSubjectRecoveryOperation = "recover" | "reset";
/** The furthest an authorization may end ahead of the store's clock: the most `mfa.manage.maxAgeSeconds` allows. */
export declare const MFA_RECOVERY_AUTHORIZATION_MAX_MS = 3600000;
/**
 * A one-time authorization to apply one recovery to one subject: `recover`,
 * minted when an exempt proof verified in the `UserSession` `sid`; `reset`,
 * by the operator reset, with no `sid`. `recoveryId` is a fresh CSPRNG value.
 */
export interface MfaSubjectRecoveryAuthorization {
    readonly operation: MfaSubjectRecoveryOperation;
    /** `recover`: the session the proof was given in; `reset`: `undefined`. */
    readonly sid: string | undefined;
    readonly recoveryId: string;
    /** After the store's clock, and no further ahead of it than {@link MFA_RECOVERY_AUTHORIZATION_MAX_MS} plus `DEFAULT_CLOCK_SKEW_MS`. */
    readonly expiresAtMs: number;
}
/** What `applySubjectRecovery` is asked to apply. */
export interface MfaSubjectRecoveryApplication {
    readonly operation: MfaSubjectRecoveryOperation;
    readonly sid: string | undefined;
    /** The caller's time, which the lock state is judged on. */
    readonly nowMs: number;
    /** The subject's lease the caller holds: the generation moves only under it. */
    readonly leaseToken: string;
    /** `recover`: the subject's sessions boundary (`revokedBefore`), `undefined` when there is none. `reset`: `undefined`. */
    readonly sessionsBoundaryMs: number | undefined;
    /**
     * `recover`, required: the earliest `createdAt` of the subject's records
     * of an installed guessable kind, unreadable ones included, or `null`
     * when none remains; records of a kind not installed are left out. A
     * value the caller could not read is never `null`. `reset`: `undefined`.
     */
    readonly guessableBoundSinceMs: number | null | undefined;
}
/** Why an apply changed nothing. */
export type MfaSubjectRecoveryRefusal = "unauthorized" | "expired" | "not_revoked_since" | "boundary_ahead" | "lease_not_held";
/**
 * The hard hold after an apply, read in the same step. While it stands,
 * `rebindAfterMs` is from when a rebind counts: the hold's time plus
 * `DEFAULT_CLOCK_SKEW_MS`, in whole epoch milliseconds, an exclusive bound —
 * a guessable record created after it is a rebind, one created at or before
 * it is not. It is the bound the apply judges a rebind by.
 */
type MfaSubjectRecoveryHold = {
    readonly hard: true;
    readonly rebindAfterMs: number;
} | {
    readonly hard: false;
    readonly rebindAfterMs: null;
};
/**
 * What `applySubjectRecovery` answers. `hard` is whether the hard hold
 * stands after the call, read in the same step, on every outcome, with from
 * when a rebind counts while it does (`rebindAfterMs`, `null` otherwise): an
 * answer never reads as released while it stands.
 */
export type MfaSubjectRecoveryAnswer = MfaSubjectRecoveryHold & ({
    readonly outcome: "applied";
    readonly recoveryId: string;
    /** The subject's generation this apply moved it to. */
    readonly generation: number;
    /**
     * What this apply gave back, each possibly empty: the week's failures,
     * the run's (and its backoff), the hard hold. A recover with nothing to
     * give back still applies, using up its authorization and moving the
     * generation.
     */
    readonly cleared: {
        readonly week: boolean;
        readonly run: boolean;
        readonly hard: boolean;
    };
} | {
    readonly outcome: "already_applied";
    readonly recoveryId: string;
    /** The generation it was applied at. */
    readonly generation: number;
} | {
    readonly outcome: "refused";
    readonly reason: MfaSubjectRecoveryRefusal;
});
/**
 * The authorization {@link MfaTransactionStore.authorizeSubjectRecovery}
 * records, its fields read once, or a `RangeError` naming what is wrong:
 * `subject` a non-empty string; `operation` and `sid` as
 * {@link MfaSubjectRecoveryAuthorization} says; `recoveryId` a non-empty,
 * well-formed string; `expiresAtMs` whole epoch milliseconds within the Date
 * range. On `storeNowMs`, the store's clock, when it is given: `expiresAtMs`
 * after it, and no further ahead than {@link MFA_RECOVERY_AUTHORIZATION_MAX_MS}
 * plus `DEFAULT_CLOCK_SKEW_MS`. An adapter whose store judges the clock in a
 * script runs the shape first and the rest on the clock that script answers.
 */
export declare function checkSubjectRecoveryAuthorization(subject: unknown, authorization: unknown, storeNowMs?: number): MfaSubjectRecoveryAuthorization;
/**
 * The application {@link MfaTransactionStore.applySubjectRecovery} acts on,
 * its fields read once, or a `RangeError` naming what is wrong: `subject` a
 * non-empty string; `operation` and `sid` as for an authorization; `nowMs` an
 * instant from the epoch within the Date range; `leaseToken` a non-empty
 * string; for `recover`, `sessionsBoundaryMs` `undefined` or whole epoch
 * milliseconds within the Date range, and `guessableBoundSinceMs` whole epoch
 * milliseconds within the Date range or `null` (none remains), never
 * absent; for `reset` both `undefined`. Every adapter calls it first.
 */
export declare function checkSubjectRecoveryApplication(subject: unknown, application: unknown): MfaSubjectRecoveryApplication;
/**
 * `answer`, what `applySubjectRecovery` answered, as the port promises it,
 * copied to its outcome's fields, each read once: a non-empty `recoveryId`,
 * a generation from 1, booleans, a refusal the port names, `rebindAfterMs`
 * whole epoch milliseconds while `hard` and `null` otherwise, never absent,
 * and an applied answer whose `cleared` and `hard` one apply can give —
 * never one that has lifted the hard hold while it still stands. `undefined`
 * for anything else, which the caller answers as the store's outage: never
 * released.
 */
export declare function readMfaSubjectRecoveryAnswer(answer: unknown): MfaSubjectRecoveryAnswer | undefined;
/**
 * Where MFA transactions, the subject lock state and its authorized recovery,
 * a subject's generation, lease and recovery-set floor, a session's
 * account-email proof and a subject's first-binding mark are kept.
 *
 * Every operation is atomic on its own. A store that cannot answer throws:
 * an outage is `503`, never a verdict on a proof.
 */
export interface MfaTransactionStore {
    readonly kind: string;
    /**
     * Insert-only: a live id is refused. A `RangeError` for an `expiresAtMs` that
     * is not a future instant, or a record {@link newMfaTransactionRecord}
     * refuses. No lifetime ceiling here: the coordinator derives `expiresAtMs`
     * only from `mfa.transactionTtlSeconds`, which boot range-checks.
     *
     * The binding then holds at most {@link MFA_MAX_TRANSACTIONS_PER_BINDING}
     * live transactions: when it already holds that many, `create` ends the
     * one of them that expires first — its oldest, since every transaction
     * lives the same `mfa.transactionTtlSeconds` — as a consume would, and
     * never the one it creates; between two that expire at one instant, which
     * goes is the store's choice. A consumed transaction, one its attempts
     * ended and an expired one do not count, and no other binding's is ever
     * ended. Replacing one this way is no new entry against a store's own
     * cap. A store whose create and its binding's count are not one atomic
     * step (the Redis adapter's, whose transactions sit on slots of their own)
     * may hold more while creates are in flight, and settles at the cap once
     * they have answered; only a step that failed leaves an excess, until it
     * expires. Such a store may also reject a create after it has written the
     * transaction (an outage at a later step): the transaction stands, unknown
     * to the caller, until it expires.
     */
    create(tx: MfaTransaction): Promise<void>;
    /** The transaction, or `null` once it expired. */
    get(id: string): Promise<MfaTransaction | null>;
    /**
     * Compare-and-set on `version`: applies `patch` ({@link MfaTransactionPatch})
     * and bumps `version`, only if still at `expectedVersion`. Answers the
     * transaction as written, or `null` when the version moved or it is gone. A
     * value a field does not admit, or an `expectedVersion` of
     * `Number.MAX_SAFE_INTEGER` (`checkMfaVersionAdvances`), is a `RangeError`
     * whatever the version.
     */
    update(id: string, expectedVersion: number, patch: MfaTransactionPatch): Promise<MfaTransaction | null>;
    /**
     * Atomic: `attempts` + 1, whatever the version. `ok` while within `max`; the
     * reservation past `max`, or one the store cannot count (fails closed),
     * deletes the transaction and answers `{ ok: false, attempts }` with the
     * attempts already reserved. No live transaction: `{ ok: false, attempts: 0 }`.
     * A `max` that is not a positive whole number is a `RangeError`.
     */
    reserveAttempt(id: string, max: number): Promise<{
        readonly ok: boolean;
        readonly attempts: number;
    }>;
    /**
     * Atomic read-and-clear of the pending challenge, only at
     * `expectedVersion`; the version stays where it was. `null` when there is
     * none, the version moved, or the transaction is gone.
     */
    takeChallenge(id: string, expectedVersion: number): Promise<MfaTransaction["challenge"] | null>;
    /** Atomic delete if still at `expectedVersion`: the one winner gets the transaction. */
    consume(id: string, expectedVersion: number): Promise<MfaTransaction | null>;
    /**
     * Refuse while a hold applies at `nowMs` — the hard hold, the short
     * backoff or the weekly budget, for every attempt alike — and otherwise
     * count a pending failure, which stands until settled. A refusal records
     * only that its episode began (`first`); an attempt let through ends the
     * episode.
     *
     * The hard hold is fixed, in the same atomic step, the first time the
     * run — reservations in flight counted — reaches `policy.hardLimit`: at
     * the reservation that brings it there, which is let through, or at the
     * first call that finds it there under a lower `hardLimit`. The store
     * records its time as the later of that call's `nowMs` and the run's
     * newest attempt, so no attempt of the run is dated after it. From then
     * until an applied recovery lifts it every reservation is refused `hard`,
     * whatever policy it is handed, and no settle, exempt success or sweep
     * lifts it.
     * The policy is read once, by {@link checkMfaLockoutPolicy}, and its
     * copy is what the call applies.
     * Of reservations racing to the limit, the one that reaches it is let
     * through and fixes the hold; those after it are refused `hard`.
     */
    reserveSubjectAttempt(subject: string, nowMs: number, policy: MfaLockoutPolicy): Promise<MfaSubjectAttemptReservation>;
    /**
     * Settle a reservation, once, under the subject that made it; settling one
     * already settled, one never made, or one under another subject changes
     * nothing. An outcome it does not know is a `RangeError`. A success or a
     * void settled once the hard hold is fixed — for the reservation that
     * fixed it included — lifts nothing of it.
     */
    settleSubjectAttempt(subject: string, reservation: string, outcome: MfaSubjectAttemptOutcome): Promise<void>;
    /**
     * An exempt success (a recovery code, a WebAuthn assertion). Before the
     * hard hold is fixed it ends the run up to `nowMs`, reservations in flight
     * among them; an attempt reserved after `nowMs` always stays. A run already
     * at `policy.hardLimit` or past it fixes the hold instead, as a reservation
     * would. Once the hold is fixed it ends nothing, whether `nowMs` is before,
     * at or after the last failure and whatever `hardLimit` it is handed. The
     * week stands, and lets no attempt through. Call it only after the
     * transaction holding the exempt proof was consumed. A `RangeError` for what
     * {@link checkMfaLockoutPolicy} refuses.
     */
    noteExemptSuccess(subject: string, nowMs: number, policy: MfaLockoutPolicy): Promise<void>;
    /**
     * Record that `subject`'s next first binding requires the 80-bit email proof,
     * whatever `mfa.enrollment.requireEmailProof` says (the operator reset's
     * `requireEmailProof: true`). Idempotent. No expiry, and an applied
     * recovery leaves it: the reset that clears the lock may not lift it.
     */
    requireEmailProofAtNextBinding(subject: string): Promise<void>;
    /** Whether the requirement is recorded for `subject`. */
    emailProofRequiredAtNextBinding(subject: string): Promise<boolean>;
    /**
     * Atomic read-and-clear at the first binding, under the subject's lease
     * held by `consume.leaseToken`: the lease checked and the requirement
     * cleared in one atomic step, so a consume that lands after the lease
     * ended — after a later reset set the requirement again — clears nothing.
     * Answers `consumed` for the one caller that cleared it, `absent` when
     * none was recorded or another cleared it first, and refuses
     * `lease_not_held` without the lease. A `RangeError`, nothing cleared, for
     * what {@link checkEmailProofRequirementConsume} refuses. Call it only
     * after the email proof was verified and the first counting factor
     * written, so a failed binding leaves the requirement standing. Keep it as
     * durably as the factor store: a lost requirement lets a password holder
     * bind without the proof.
     */
    consumeEmailProofRequirement(subject: string, consume: MfaEmailProofRequirementConsume): Promise<MfaEmailProofRequirementConsumeAnswer>;
    /**
     * Record the account-email proof (D24) given in the session `sid` of
     * `subject` at `provedAtMs`, standing until `untilMs`; it replaces an
     * earlier one for that session. A `RangeError`, nothing recorded, for what
     * {@link checkSessionEmailProof} refuses on the store's clock.
     */
    recordSessionEmailProof(subject: string, sid: string, provedAtMs: number, untilMs: number): Promise<void>;
    /**
     * What {@link sessionEmailProofAnswer} answers of the proof recorded for
     * the session `sid` of `subject`, on the store's clock: when it was given,
     * no later than `nowMs`, while it stands; else `null`. Another session's
     * proof, or the same `sid` under another subject, never answers. A
     * `RangeError` for what {@link checkSessionEmailProofQuestion} refuses.
     */
    sessionEmailProofAt(subject: string, sid: string, nowMs: number): Promise<number | null>;
    /**
     * Note that a first counting factor was bound for `subject`, or its
     * witness marked, at `atMs`, standing until `untilMs` on the store's clock.
     * The store keeps {@link laterFirstBindingMark} of the mark held and this
     * one: the later `atMs` and the later `untilMs`, so no note moves a mark
     * back or shortens it. An applied recovery leaves it. Answers what
     * {@link firstBindingAnswer} answers of the mark that stood before this
     * note, on the same clock: its `atMs`, or `null` when none stood. The
     * read and the write are one atomic step, so of notes in flight each
     * answers the mark another left, and one at most answers `null`. A
     * `RangeError`, nothing noted, for what {@link checkFirstBindingNote}
     * refuses on the store's clock.
     */
    noteFirstBinding(subject: string, atMs: number, untilMs: number): Promise<number | null>;
    /**
     * What {@link firstBindingAnswer} answers of `subject`'s mark: `atMs`
     * while the mark stands on the store's clock, else `null`. One clock
     * decides its end, the store's: `nowMs` never ends a mark. The answer is
     * never clamped to `nowMs`: an earlier answer would trust a session the
     * mark distrusts. A `RangeError` for what {@link checkFirstBindingQuestion}
     * refuses. A store that cannot read the mark it holds rejects: an absent
     * mark trusts the session.
     */
    firstBindingAt(subject: string, nowMs: number): Promise<number | null>;
    /**
     * The subject's generation: 0 until a recovery or a reset is first
     * applied, then one more for each. A writer captures it before the
     * request that writes is admitted, or at the begin of the ceremony and
     * carried with it, and acquires the lease under it. A `RangeError` for
     * what {@link checkSubjectQuestion} refuses.
     */
    subjectGeneration(subject: string): Promise<number>;
    /**
     * In one step: `stale` when `request.generation` is not the subject's
     * generation; else `busy` while another holder's lease stands;
     * else a lease standing `ttlMs` on the store's clock, under a fresh token.
     * The generation moves only under the lease
     * (`applySubjectRecovery`), so it stays the one acquired under until the
     * lease ends. A `RangeError`, nothing held, for what
     * {@link checkSubjectLeaseRequest} refuses.
     */
    acquireSubjectLease(subject: string, request: MfaSubjectLeaseRequest): Promise<MfaSubjectLeaseAnswer>;
    /**
     * Ends the lease `token` holds: `true` when it still held it, so no other
     * holder moved the generation while it stood; `false` when the lease had
     * ended, or another holds it, which it leaves. A `RangeError` for what
     * {@link checkSubjectLeaseRelease} refuses.
     */
    releaseSubjectLease(subject: string, token: string): Promise<boolean>;
    /**
     * Records `authorization` in the subject's slot for its operation and
     * `sid`, replacing whatever the slot held, pending or applied. It touches
     * no lock state, generation or lease. A `RangeError`, nothing recorded,
     * for what {@link checkSubjectRecoveryAuthorization} refuses on the
     * store's clock.
     */
    authorizeSubjectRecovery(subject: string, authorization: MfaSubjectRecoveryAuthorization): Promise<void>;
    /**
     * Applies the authorization in the slot for `application`'s operation and
     * `sid`, in one step, refusing in this order:
     *
     * - `lease_not_held`: the subject's lease is not held under `leaseToken`.
     * - `unauthorized`: the slot is empty, or its authorization has ended on
     *   the store's clock. A slot already applied answers `already_applied`,
     *   with the generation it was applied at. `expired`: it ends at or before
     *   `nowMs`.
     * - `recover` only. `boundary_ahead`: `sessionsBoundaryMs` is later than
     *   `nowMs` plus `DEFAULT_CLOCK_SKEW_MS`. `not_revoked_since`: the week
     *   counts a failure dated up to `nowMs` (a reservation in flight is one) and
     *   `sessionsBoundaryMs` is absent or not later than the earliest such
     *   failure by more than `DEFAULT_CLOCK_SKEW_MS`, and no hard hold is
     *   lifted.
     *
     * A `recover` lifts the hard hold on a rebind: `guessableBoundSinceMs` is
     * `null` or later than the hold's time by more than `DEFAULT_CLOCK_SKEW_MS`.
     * Every answer, a refusal's included, carries that bound while the hold
     * stands after the call (`rebindAfterMs`).
     * No sessions boundary is asked for, and the run the hold counted ends
     * with it, its backoff included: every attempt in it was against the
     * replaced authenticators. The week stands unless the boundary gives it
     * back. With the boundary, a `recover` ends the week's and the run's
     * attempts dated up to `nowMs`; while the hard hold stands, the week's
     * alone. A `reset` asks for neither: it ends the subject's lock state
     * whole, the hard hold included, and every other authorization of the
     * subject. A refusal changes nothing, and the authorization stays pending
     * until it ends. Applied, the slot is marked applied (kept until it ends)
     * and the subject's generation moves on by one. The email-proof
     * requirement, the first-binding mark, session proofs and transactions
     * are not lock state and stay. A `RangeError`, nothing changed, for what
     * {@link checkSubjectRecoveryApplication} refuses.
     */
    applySubjectRecovery(subject: string, application: MfaSubjectRecoveryApplication): Promise<MfaSubjectRecoveryAnswer>;
    /**
     * Under the subject's lease held by `raise.leaseToken`, raises the
     * subject's recovery-set floor to `raise.setGeneration` — a recovery-code
     * set's generation, not the subject's — when it is higher, and answers
     * the floor after; without the lease, refuses `lease_not_held`, raising
     * nothing. Nothing lowers it: not a deleted set, a reset or a sweep. A
     * `RangeError`, nothing raised, for what {@link checkRecoverySetFloorRaise}
     * refuses.
     */
    raiseRecoverySetFloor(subject: string, raise: MfaRecoverySetFloorRaise): Promise<MfaRecoverySetFloorAnswer>;
    /**
     * The subject's recovery-set floor, 0 when none was raised: a set of a
     * lower set generation verifies no code. A `RangeError` for what
     * {@link checkSubjectQuestion} refuses.
     */
    recoverySetFloor(subject: string): Promise<number>;
}
/** Domain-specific AdapterFactory alias for {@link MfaTransactionStore}. */
export type MfaTransactionStoreFactory = AdapterFactory<MfaTransactionStore>;
/**
 * The store's port check. Refuses a lockout policy a store cannot apply as
 * written, with a `RangeError` naming `setting` and the field: an object,
 * every field a positive whole number, `maxSeconds` ≥ `baseSeconds`,
 * `threshold` ≤ `hardLimit` (a threshold above it is never reached),
 * `hardLimit` ≤ {@link MFA_LOCKOUT_MAX_HARD_LIMIT}, and every duration ending
 * within the Date range. Every store operation taking a policy calls it. A
 * policy a deployment configures is checked by
 * {@link checkConfiguredMfaLockoutPolicy}, which runs this first and adds its
 * own bounds (a `hardLimit` floor, a `maxSeconds` cap). Answers the policy it checked, each field read once: a store applies
 * that copy, so what it applies is what was checked.
 *
 * @param setting - where the policy was read from, for the message.
 */
export declare function checkMfaLockoutPolicy(policy: MfaLockoutPolicy, setting?: string): Readonly<MfaLockoutPolicy>;
/**
 * Checks a lockout policy a deployment configures: the store's port check
 * ({@link checkMfaLockoutPolicy}), then its own bounds. A `RangeError`
 * naming `setting` and the reason refuses a `hardLimit` below
 * {@link MFA_LOCKOUT_MIN_HARD_LIMIT}, one not above `threshold`, or a
 * `maxSeconds` above {@link MFA_LOCKOUT_MAX_BACKOFF_SECONDS}. Answers the
 * port check's copy.
 *
 * @param setting - where the policy was read from, for the message.
 */
export declare function checkConfiguredMfaLockoutPolicy(policy: MfaLockoutPolicy, setting?: string): Readonly<MfaLockoutPolicy>;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /** MFA transactions and the subject lock state. */
        readonly mfaTransactionStore?: MfaTransactionStore;
    }
}
export {};
//# sourceMappingURL=transactionStore.d.mts.map