/**
 * The contract the MFA ceremonies share: a call, what each ceremony answers,
 * and the kit the coordinator hands the ceremonies beside a verification —
 * an enrollment (`enrollment.mts`), the account-email proof (`proof.mts`),
 * a session's step-up opened (`stepUp.mts`) and a login reopened for a binding
 * (`reopen.mts`). A leaf: the coordinator and the
 * ceremonies import it, and it imports none of them, so no two of them
 * depend on each other's contracts.
 */
import type { InterruptionAnswer, MailSender, MfaFactor, MfaFactorData, MfaFactorRecord, MfaFactorResolver, MfaFactorStore, MfaSubjectHold, MfaTransaction, MfaTransactionBinding, MfaTransactionPatch, MfaVerification, PrimaryContinuation } from "@o3co/auth-provider-core";
import type { MfaFactorSet, MfaFactorSetStart } from "./factorSet.mjs";
import type { MfaSubjectRecords } from "./factorState.mjs";
import type { RequireEmailProof, UnprovableReason } from "./firstBinding.mjs";
import type { MfaMailRefusal } from "./mail.mjs";
import type { MfaIssuedRecoveryCodes, MfaUnshownRecoveryCodes } from "./recovery/issue.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";
/** The store that could not answer: an MFA store, or the subjects' sessions boundary. */
export type MfaStoreName = "mfa_transaction" | "mfa_factor" | "revocation_boundary";
/** A store that could not answer: the operation, and why. */
export interface MfaStoreOutage {
    readonly outcome: "unavailable";
    readonly store: MfaStoreName;
    readonly step: string;
    readonly cause: unknown;
}
/** A store's outage at `step`. */
export declare const outage: (store: MfaStoreName, step: string, cause: unknown) => MfaStoreOutage;
/** Why a store's answer outside its port's promise is an outage: it is never read as a verdict. */
export declare const OUTSIDE_CONTRACT: TypeError;
/**
 * A factor that cannot be used as stored: its data does not open
 * (`unreadable`), or opens under a key the ring lacks (`key_unavailable`,
 * naming it), or the factor threw reading it (`verification`); or its
 * pending challenge's kept state does not open (`challenge`, naming the key
 * when it is the one missing); or a first binding's pending enrollment does
 * not open, or the factor threw completing it (`enrollment`).
 */
export interface MfaFactorUnreadable {
    readonly outcome: "unreadable";
    readonly kind: string;
    readonly factorId: string;
    readonly state: "unreadable" | "key_unavailable" | "verification" | "challenge" | "enrollment";
    readonly keyId?: string;
    readonly cause?: unknown;
}
/** Who and what an outcome concerns, for its audit event. */
export interface MfaCeremonySubject {
    readonly subject: string;
    readonly kind: string;
    readonly purpose: MfaTransaction["purpose"];
}
/** No usable transaction: unknown, foreign, spent, expired, or not a login's. */
export declare const UNKNOWN_TRANSACTION: Readonly<{
    outcome: "unknown_transaction";
}>;
/** No factor of the subject's that an installed factor verifies, by the id named. */
export declare const UNKNOWN_FACTOR: Readonly<{
    outcome: "unknown_factor";
}>;
export type UnknownTransaction = typeof UNKNOWN_TRANSACTION;
export type UnknownFactor = typeof UNKNOWN_FACTOR;
/**
 * A login transaction of `subject` whose continuation was authenticated at
 * or before the subject's sessions boundary — a revocation or a password
 * change since: it completes nothing, and the user signs in again.
 */
export interface Revoked {
    readonly outcome: "revoked";
    readonly subject: string;
}
/**
 * A first binding of `subject` whose authentication — the login's, or the
 * session's — the subject's first-binding mark distrusts
 * (`firstBindingMark.mts`): nothing is spent or written, and the user signs
 * in again, binding once `retryAfterMs` has passed on this clock.
 */
export interface MfaFirstBindingDistrusted {
    readonly outcome: "first_binding_distrusted";
    readonly subject: string;
    readonly retryAfterMs: number;
}
/**
 * The signed-in session a ceremony outside a login runs in, as the route
 * admitted it: its `sid`, its subject, the `User` its cookie holds (core's
 * `cookieSessionUser`), its primary sign-in as admission's view holds
 * it — `undefined` without one, which any first-binding mark distrusts —
 * whether that sign-in was a federation's, and the enrollment witness its
 * login's `User` carried as admission's view holds it, `undefined` when it
 * recorded none.
 */
export interface MfaCeremonySession {
    readonly sid: string;
    readonly subject: string;
    readonly user: Readonly<Record<string, unknown>>;
    readonly authTimeMs: number | undefined;
    /** Whether the session was signed in through a federation, as core's `sessionAuthentication` reads its record; `false` when that cannot be told. */
    readonly federated: boolean;
    readonly witness: "enrolled" | "not_enrolled" | "malformed" | undefined;
    /**
     * Whether a second factor can be recorded on the session, as admission's
     * view holds it (`secondFactorRecordable`); `false` without a view. A
     * step-up is opened only when it is `true`.
     */
    readonly secondFactorRecordable: boolean;
    /** Where a write to the subject's factor set begins, taken before the session was admitted for one (`factorSet.mts`); none for an action that writes none. */
    readonly factorSetStart?: MfaFactorSetStart;
}
/** One call's request: the transaction named, the binding the browser presents, and what a factor may read of the request. */
export interface MfaCeremonyCall {
    readonly transactionId: string | undefined;
    readonly binding: MfaTransactionBinding;
    readonly request: {
        readonly ip?: string;
        readonly userAgent?: string;
    };
    /** The session the call was admitted in; none for a login's ceremony, whose browser holds none yet. */
    readonly session?: MfaCeremonySession;
}
/** What a transaction's reader is shown of it. */
export interface MfaTransactionView {
    readonly purpose: MfaTransaction["purpose"];
    readonly factors: readonly {
        readonly id: string;
        readonly kind: string;
        readonly label?: string;
        readonly hint?: string;
    }[];
    readonly enrollment: MfaTransaction["enrollment"];
    readonly emailProof: boolean;
    readonly expiresIn: number;
    readonly attemptsRemaining: number;
}
/** A refused proof, with what is left of the transaction's attempts. */
export type MfaRefusalReason = Extract<MfaVerification, {
    ok: false;
}>["reason"] | "exhausted";
export type MfaDescribeOutcome = UnknownTransaction | Revoked | MfaStoreOutage | {
    readonly outcome: "described";
    readonly view: MfaTransactionView;
};
export type MfaChallengeOutcome = UnknownTransaction | Revoked | UnknownFactor | MfaStoreOutage | MfaFactorUnreadable | MfaMailRefusal | {
    readonly outcome: "none";
} | ({
    readonly outcome: "sent";
    readonly response: object;
} & MfaCeremonySubject)
/** A login code whose factor recorded another address, or none it can read: the factor is refused. */
 | ({
    readonly outcome: "address_mismatch";
} & MfaCeremonySubject)
/** The account-email proof is asked for and nobody can give it: no sender, or no address. */
 | {
    readonly outcome: "proof_unavailable";
} | {
    readonly outcome: "challenge_failed";
    readonly kind: string;
    readonly factorId: string;
    readonly cause: unknown;
};
export type MfaVerifyOutcome = UnknownTransaction | Revoked | UnknownFactor | MfaStoreOutage | MfaFactorUnreadable | ({
    readonly outcome: "refused";
    readonly reason: MfaRefusalReason;
    readonly attemptsRemaining: number;
    /** The subject's factor the refusal concerns, as the factor named it (a clone's). */
    readonly factorId?: string;
    /** The factor named an id that is none of the subject's factors of this kind: left out. */
    readonly factorIdDropped?: true;
} & MfaCeremonySubject)
/** The proof was right, and another verification consumed the transaction first. */
 | {
    readonly outcome: "spent";
}
/** A guessable proof the subject's hold refused, unchecked (the MFA ADR's D21). */
 | ({
    readonly outcome: "locked";
    readonly hold: MfaSubjectHold;
    /** Milliseconds until an attempt may be reserved; `null` for the hard hold. */
    readonly retryAfterMs: number | null;
    /** Whether this refusal begins an episode. */
    readonly first: boolean;
    /** The exempt kinds the subject holds: what a hold does not refuse. */
    readonly exemptKinds: readonly string[];
    /** The transaction's attempts left: the refusal spent one. */
    readonly attemptsRemaining: number;
    /** What authorized the refused attempt's factor. */
    readonly binding: MfaFactorRecord["binding"];
} & MfaCeremonySubject)
/** The account-email proof was given: the first binding may proceed. */
 | ({
    readonly outcome: "proved";
} & MfaCeremonySubject)
/**
 * The proof was right and spent, but it does not count and the subject
 * holds no counting factor it can use (F3): the login's own `403`, naming
 * the transaction reopened for a binding.
 */
 | ({
    readonly outcome: "binding_reopened";
    readonly answer: InterruptionAnswer;
    /** The codes the set holds once a recovery code was spent; `undefined` for any other factor. */
    readonly recoveryCodesRemaining: number | undefined;
} & MfaCeremonySubject)
/** As `binding_reopened`, but the new transaction could not be opened: the proof stays spent. */
 | ({
    readonly outcome: "binding_not_reopened";
    readonly outage: MfaStoreOutage;
    readonly recoveryCodesRemaining: number | undefined;
} & MfaCeremonySubject) | (MfaReopenRefusal & MfaCeremonySubject) | ({
    readonly outcome: "verified";
    /** What the login persisted, as the store answered it at consumption. */
    readonly continuation: PrimaryContinuation | undefined;
    /** What the verification adds to the login: the factor's `amr`, `mfa` when it adds it, and when. */
    readonly adds: {
        readonly amr: readonly string[];
        readonly mfaAt: Date;
    };
    /** The witness marked for a login's `User` that lacked it; `undefined` when none was due, or no mark was noted before it. */
    readonly witness: MfaWitnessMark | undefined;
    /** Why the first-binding mark due before the witness could not be noted, leaving the witness unmarked; `undefined` otherwise. */
    readonly firstBindingUnnoted: MfaStoreOutage | undefined;
    /** The codes the set holds once a recovery code was spent; `undefined` for any other factor. */
    readonly recoveryCodesRemaining: number | undefined;
} & MfaCeremonySubject)
/**
 * A session's step-up verified, its transaction consumed and the factor
 * moved on: the session `sid` is to be escalated by `adds`, which the
 * ceremony records nowhere.
 */
 | ({
    readonly outcome: "stepped_up";
    readonly sid: string;
    /** What the verification adds to the session: the factor's `amr`, `mfa` when it adds it, and when. */
    readonly adds: {
        readonly amr: readonly string[];
        readonly mfaAt: Date;
    };
    /** The witness marked for a session whose recorded `User` lacked it; `undefined` when none was due, or no mark was noted before it. */
    readonly witness: MfaWitnessMark | undefined;
    /** Why the first-binding mark due before the witness could not be noted, leaving the witness unmarked; `undefined` otherwise. */
    readonly firstBindingUnnoted: MfaStoreOutage | undefined;
    /** The codes the set holds once a recovery code was spent; `undefined` for any other factor. */
    readonly recoveryCodesRemaining: number | undefined;
} & MfaCeremonySubject);
/**
 * Why a login is not reopened for a binding, answered before anything is
 * spent: a first binding while the login's `User` says the subject enrolled,
 * or says nothing readable (D12); no counting factor offered to the user, or
 * one that cannot say (each an outage); or a binding nobody could complete —
 * a proof the gate asks that nobody can give, or `mfa.maxFactorsPerSubject`
 * reached beside a record that may count.
 */
export type MfaReopenRefusal = MfaFirstBindingDistrusted | {
    readonly outcome: "enrollment_state_inconsistent";
    readonly witness: "enrolled" | "malformed";
} | {
    readonly outcome: "nothing_enrollable";
    readonly countingKinds: readonly string[];
} | {
    readonly outcome: "enrollable_failed";
    readonly factorKind: string;
    readonly cause: unknown;
} | {
    readonly outcome: "binding_refused";
    readonly unprovable: UnprovableReason | undefined;
};
/** Why an enrollment is refused before anything is spent. */
export type MfaEnrollmentRefusal = UnknownTransaction | Revoked | MfaFirstBindingDistrusted | MfaStoreOutage
/** The transaction opened no enrollment, or it is not a login's first binding. */
 | {
    readonly outcome: "enrollment_not_open";
}
/** The account-email proof is owed first. */
 | {
    readonly outcome: "email_proof_required";
}
/** No counting factor of that kind this user may enroll. */
 | {
    readonly outcome: "unknown_kind";
}
/**
 * The subject's records no longer allow the binding: a first binding's
 * subject holds a record now, or the factor it would go beside is gone —
 * a login starts again; a session, which stands, starts the enrollment
 * again.
 */
 | {
    readonly outcome: "first_binding_closed";
    readonly purpose: MfaTransaction["purpose"];
}
/** The subject holds `mfa.maxFactorsPerSubject` records. */
 | {
    readonly outcome: "factor_limit";
}
/**
 * The factor is enrolled already: a record of the subject, of its kind,
 * answers the identity the binding would add (`MfaFactor.identity`).
 */
 | {
    readonly outcome: "factor_duplicate";
};
/**
 * The factor could not start its enrollment, or could not say whether the
 * user may enroll it (`MfaEnrollableError`): an outage, never a refusal.
 */
export interface MfaEnrollmentFailed {
    readonly outcome: "enrollment_failed";
    readonly kind: string;
    readonly cause: unknown;
}
/** An `enroll` transaction as the page names it next: its id, and the seconds it has left. */
export interface MfaOpenedTransaction {
    readonly id: string;
    readonly expiresIn: number;
}
export type MfaEnrollmentBeginOutcome = MfaEnrollmentRefusal | MfaMailRefusal | MfaEnrollmentFailed | ({
    readonly outcome: "begun";
    readonly response: object;
    /** An `enroll` transaction's, which the page completes the enrollment on. */
    readonly transaction?: MfaOpenedTransaction;
    /**
     * How long the enrollment begun can be completed, in seconds, when that
     * is shorter than its transaction's life: a mailed code's.
     */
    readonly expiresIn?: number;
} & MfaCeremonySubject);
export type MfaEnrollmentCompleteOutcome = (MfaEnrollmentRefusal | MfaEnrollmentFailed | MfaFactorUnreadable | {
    readonly outcome: "no_pending_enrollment";
}
/**
 * Another write held the subject's factor set past the wait: nothing was
 * written and the transaction stands; the attempt the completion reserved
 * before its proof was checked counts, as any completion's does.
 */
 | {
    readonly outcome: "factors_busy";
    readonly retryAfterSeconds: number;
} | {
    readonly outcome: "invalid_label";
} | {
    readonly outcome: "spent";
} | ({
    readonly outcome: "refused";
    readonly reason: MfaRefusalReason;
    readonly attemptsRemaining: number;
} & MfaCeremonySubject)
/**
 * A first binding its read before the subject's lease let through, refused
 * by a record that may count found by its read under the lease: another
 * binding of the subject landed between the two. Nothing was written and
 * the transaction stands; answered as `first_binding_closed`, and audited.
 */
 | ({
    readonly outcome: "first_binding_conflict";
} & MfaCeremonySubject) | ({
    readonly outcome: "enrolled";
    /** What the login persisted, as the store answered it at consumption. */
    readonly continuation: PrimaryContinuation | undefined;
    /**
     * What the binding adds to the login it completes, or to the session it
     * is made in: the factor's `amr`, `mfa` when it adds it, and when.
     * `undefined` for a binding that counts only from the next sign-in that
     * uses its factor (`enrollment.mts`): it completes no login and
     * escalates no session.
     */
    readonly adds: {
        readonly amr: readonly string[];
        readonly mfaAt: Date;
    } | undefined;
    readonly factor: {
        readonly id: string;
        readonly kind: string;
        readonly label?: string;
    };
    readonly binding: NonNullable<MfaFactorRecord["binding"]>;
    /** A login's set is written unshown: the answer that carries its codes marks it (`show`). */
    readonly recoveryCodes: MfaIssuedRecoveryCodes | MfaUnshownRecoveryCodes;
    /** The witness marked after a first binding; `undefined` for a factor bound beside another. */
    readonly witness: MfaWitnessMark | undefined;
    /** Why D25's flag could not be cleared after the proof was given; `undefined` when it was, or none was due. */
    readonly flagUncleared: unknown;
} & MfaCeremonySubject)) & {
    /** The binding's writes ran past the subject's lease: a reset or a recovery may have run beside them. */
    readonly overran?: true;
};
/**
 * What a session's step-up answers: for a subject with no record that may
 * count, the `enroll` transaction the account-email proof is owed on; for
 * one holding a record that may count, the `step_up` transaction its factor
 * is verified on; or why none.
 */
export type MfaStepUpOutcome = UnknownTransaction | MfaStoreOutage
/** No second factor can be recorded on the session (`MfaCeremonySession.secondFactorRecordable`): it logs in again instead. */
 | {
    readonly outcome: "step_up_unrecordable";
}
/** The subject holds no record of an installed kind whose data opens: nothing could step it up. */
 | {
    readonly outcome: "no_qualifying_factor";
} | {
    readonly outcome: "opened";
    readonly transaction: MfaOpenedTransaction;
    /** Whether the account-email proof is owed on it: a first binding's, never a step-up's. */
    readonly emailProof: boolean;
};
/**
 * What the ceremonies beside a verification share of the coordinator: its
 * stores, and the reads and writes every use of a transaction goes through,
 * each answering an outage as a verification does.
 */
export interface MfaCeremonyKit {
    readonly factors: MfaFactorResolver;
    readonly factorStore: Pick<MfaFactorStore, "update">;
    readonly sealing: MfaSealing;
    readonly mailSender: MailSender | undefined;
    readonly witness: MfaEnrollmentWitness;
    /** The subject's factor set: where an enrollment's start is taken and carried, and its writes run under the subject's lease. */
    readonly factorSet: MfaFactorSet;
    readonly now: () => number;
    /** `mfa.maxFactorsPerSubject`: the records a subject may hold before an enrollment in a session is refused. */
    readonly maxFactorsPerSubject: number;
    /** `mfa.enrollment.requireEmailProof`, which the gate of a login reopened for a first binding reads. */
    readonly requireEmailProof: RequireEmailProof;
    /**
     * The transaction `call` names, bound to its binding: a login's, or an
     * `enroll` or `step_up` one whose `sid` and subject are `call.session`'s;
     * `null` when there is none to use; `revoked` for a login's past its
     * subject's sessions boundary.
     */
    readonly bound: (call: MfaCeremonyCall) => Promise<MfaTransaction | null | Revoked | MfaStoreOutage>;
    /** As `bound`, for an `enroll` or `step_up` transaction of `call.session` alone: a login's is none, and its boundary is never read. */
    readonly boundInSession: (call: MfaCeremonyCall) => Promise<MfaTransaction | null | MfaStoreOutage>;
    /**
     * Whether `subject`'s first-binding mark distrusts an authentication at
     * `authTimeMs` (`firstBindingMark.mts`): the refusal; `undefined` when it
     * does not, or there is none; the outage when it cannot be read.
     */
    readonly firstBindingDistrust: (subject: string, authTimeMs: number | undefined) => Promise<MfaFirstBindingDistrusted | MfaStoreOutage | undefined>;
    /**
     * `subject`'s first-binding mark noted at the clock's reading as it is
     * noted, standing its lifetime, and the mark that stood before it — which
     * the store answers in the same step — judged as `firstBindingDistrust`
     * judges: the refusal when it distrusts an authentication at
     * `authTimeMs`; `undefined` when it does not, or none stood; the outage
     * when the mark could not be noted or the answer is outside the port.
     */
    readonly noteFirstBinding: (subject: string, authTimeMs: number | undefined) => Promise<MfaFirstBindingDistrusted | MfaStoreOutage | undefined>;
    /**
     * D12's reconciliation for `subject`, just verified with a counting factor
     * its `User` does not say it enrolled: the first-binding mark noted, then
     * the witness marked — only once the mark was noted, never by a directory
     * that cannot write it, and held to `started`, read before the proof was
     * checked. Never throws.
     */
    readonly reconcileWitness: (subject: string, started: MfaFactorSetStart | undefined) => Promise<{
        readonly witness: MfaWitnessMark | undefined;
        readonly firstBindingUnnoted: MfaStoreOutage | undefined;
    }>;
    /** A new `enroll` transaction for `session`, bound to the browser `call` presents; the outage otherwise. */
    readonly openEnrollment: (call: MfaCeremonyCall, session: MfaCeremonySession, shape: {
        readonly enrollment: "required" | "allowed";
        readonly emailProof: "required" | "not_required";
    }) => Promise<MfaTransaction | MfaStoreOutage>;
    /** A new `step_up` transaction for `session`, bound to the browser `call` presents, recording `acrValues`; the outage otherwise. */
    readonly openStepUp: (call: MfaCeremonyCall, session: MfaCeremonySession, acrValues: readonly string[] | undefined) => Promise<MfaTransaction | MfaStoreOutage>;
    /**
     * Whether the subject `read` holds a usable record of any kind
     * (`factorState.mts`'s `holdsUsableIn`: of an installed kind, its data
     * opening, a recovery set with a code left at or above the floor).
     */
    readonly holdsUsable: (read: MfaSubjectRecords) => boolean;
    /** The subject's records read for a judgment over them (`factorState.mts`'s `readSubjectRecords`); a listing that fails is the outage. */
    readonly readSubject: (subject: string) => Promise<MfaSubjectRecords | MfaStoreOutage>;
    /** Whether the account-email proof given in the session `sid` of `subject` stands now; the outage otherwise. */
    readonly provedInSession: (subject: string, sid: string) => Promise<boolean | MfaStoreOutage>;
    /**
     * A new login transaction over `continuation`, bound to `binding`, opened
     * for the binding `shape` says: the login's `403` naming it; the outage
     * otherwise.
     */
    readonly openLoginBinding: (binding: MfaTransactionBinding, continuation: PrimaryContinuation, shape: {
        readonly enrollment: "allowed" | "required";
        readonly enrollable: readonly string[];
        readonly emailProof: boolean;
    }) => Promise<InterruptionAnswer | MfaStoreOutage>;
    /** The account-email proof given at `provedAtMs` in the session `sid` of `subject`, recorded to stand `mfa.manage.maxAgeSeconds`; the outage otherwise. */
    readonly recordSessionProof: (subject: string, sid: string, provedAtMs: number) => Promise<MfaStoreOutage | undefined>;
    /** Every record of `subject`, oldest first; an outage is never "none". */
    readonly recordsOf: (subject: string) => Promise<MfaFactorRecord[] | MfaStoreOutage>;
    /** One of `tx`'s attempts reserved: the attempts left, `exhausted` past the limit, or why none was. */
    readonly reserve: (tx: MfaTransaction) => Promise<{
        readonly attemptsRemaining: number;
    } | {
        readonly outcome: "exhausted";
    } | UnknownTransaction | MfaStoreOutage>;
    /** `tx` consumed at the version read, or `spent`, or the outage. */
    readonly consume: (tx: MfaTransaction) => Promise<MfaTransaction | {
        readonly outcome: "spent";
    } | MfaStoreOutage>;
    /**
     * `patch` written at `tx`'s version: the transaction the store answered —
     * its id and next version checked — else why not.
     */
    readonly write: (tx: MfaTransaction, patch: MfaTransactionPatch) => Promise<{
        readonly written: MfaTransaction;
    } | UnknownTransaction | MfaStoreOutage>;
    /**
     * `field` cleared on `written`, the transaction as a keep wrote it: `true`
     * only once the store wrote the clear as asked — never for an answer of
     * `null`, one outside its port, or a failure.
     */
    readonly clear: (written: MfaTransaction, field: "challenge" | "pendingEnrollment") => Promise<boolean>;
    /** D25's flag for `subject`; an outage — an answer that is not a boolean among it — otherwise. */
    readonly emailProofRequired: (subject: string) => Promise<boolean | MfaStoreOutage>;
    /** A copy of `factor.amrFor(data)`, taken once, when it names at least one value and only values the factor declares; else `undefined`. */
    readonly declaredAmr: (factor: MfaFactor, data: MfaFactorData) => readonly string[] | undefined;
    /**
     * `factor.identity(data)` when it answers a non-empty string; else
     * `undefined`, a duplicate of none — a throw too, which is said (`identityFailed`).
     */
    readonly identityOf: (factor: MfaFactor, data: MfaFactorData) => string | undefined;
}
//# sourceMappingURL=ceremony.d.mts.map