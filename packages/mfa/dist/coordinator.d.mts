/**
 * The coordinator: a login's second-factor ceremony, and an enrollment or an
 * account-email proof in a signed-in session, over the MFA stores, the key
 * ring and the installed factors — reading the transaction, issuing a
 * factor's challenge, verifying a proof — answered as outcomes the routes map
 * to HTTP. See README, "The routes", and ADR
 * 2026-09-25-multi-factor-authentication, F1, F2, F4 and D8.
 *
 * - Every operation starts with the bound read (`getBoundMfaTransaction`), and
 *   after it calls only operations that carry the version it read, and
 *   `reserveAttempt` once it held. A transaction bound to anything else,
 *   spent, expired, neither a login's nor an `enroll` or `step_up` one of
 *   the session the call was admitted in — its `sid` and subject — reads as
 *   unknown, and spends nothing. An `enroll` transaction verifies the
 *   account-email proof alone.
 * - A login's transaction is held to its subject's sessions boundary
 *   (`revokedBefore`) at every bound read: a continuation authenticated at or
 *   before it, the revocation skew allowed, is `revoked` and spends nothing;
 *   a boundary that cannot be read is an outage; none wired, none is read.
 *   The step-up reads only its session's `enroll` and `step_up`
 *   transactions, so it never reads a login's boundary. The boundary is read once per call: a
 *   revocation landing during that call can still let it bind.
 * - The step-up of a subject with no record that may count opens, or uses,
 *   an `enroll` transaction owing the account-email proof (`stepUp.mts`); a verified proof
 *   on one is recorded for its session alone, standing
 *   `mfa.manage.maxAgeSeconds`. The step-up of a subject holding one opens,
 *   or uses, a `step_up` transaction, opened only where admission's view says
 *   a second factor can be recorded on the session
 *   (`MfaCeremonySession.secondFactorRecordable`).
 * - A verification reserves its attempt before the proof is checked, consumes
 *   the transaction before the factor moves on, and on a lost compare-and-set
 *   reads the factor again and checks the proof again: a code used twice at
 *   once succeeds once, and a lost race never spends a factor's state.
 * - Between the two, the subject lock (`lock.mts`): a guessable proof
 *   reserves one of its subject's attempts after the transaction's, and a
 *   hold refuses it unchecked. The attempt is settled once the verification
 *   ends: `success` once the factor was written, `void` for a right proof
 *   that completed nothing, and a failure otherwise — a refusal, an outage
 *   or a factor that throws before a verdict. An exempt proof records its
 *   success once the factor was written. A right proof whose factor answers
 *   data that cannot be sealed (`copyFactorValue`), the data it was handed
 *   included, is `void` too — the factor's bug never counts against the
 *   subject — and is answered `503` before anything is consumed: the
 *   transaction kept and still usable, its attempt counted at the
 *   reservation, the factor's data as it was.
 * - A recovery code's verification reads the subject's recovery-set floor
 *   before its attempt is reserved, and again once the code is spent: a set
 *   the recovery-code rule refuses (`recoverySetRefusal`) — below the floor —
 *   is an invalid code, refused unchecked before, its transaction spent
 *   after; a digest whose key left the ring is unreadable, naming the key.
 * - A store that cannot answer, a factor whose data does not open, and a
 *   factor that throws are outages: never a wrong code, never "no factor".
 * - `factor_id: "account-email"` names the account-email proof (`proof.mts`)
 *   on a transaction that owes it; a first binding is `enrollment.mts`'s.
 *   Both are handed the coordinator's reads and writes as the kit; what the
 *   three share is `ceremony.mts`'s contract.
 * - Under `required`, a login's factor that does not count, for a subject
 *   with no counting factor it can use, completes no login: what the login
 *   reopens for — or why not — is settled before the transaction's attempt is
 *   reserved (`reopen.mts`), and settled again after a lost compare-and-set
 *   round; once the transaction is consumed and the proof spent, the login is
 *   reopened for a binding. A login transaction opened for a binding
 *   verifies no factor.
 * - A verified proof on a session's `step_up` transaction is answered
 *   `stepped_up`, naming the session and what the proof adds, dated by the
 *   verification's time: the caller records it on the session. The factor's
 *   mailed code goes to the session's own address.
 * - A verified counting factor marks the enrollment witness of a login — or
 *   a step-up's session — whose `User` does not carry it (D12), after noting the subject's first-binding
 *   mark (`firstBindingMark.mts`): a note that fails leaves the witness
 *   unmarked, so no session's recorded witness goes stale unmarked; a
 *   directory that cannot write the witness gets no note. Neither failure
 *   fails the login (`reconcileWitness`). The mark is `factorSet.mts`'s,
 *   held to the subject's generation read before the proof is checked: it
 *   reads the records first, and clears the witness again when the records
 *   read after it hold none that may count.
 * - A factor is handed its records opened and digests under the ring; it
 *   never sees a key, a store, a transaction or the mail sender. A code it
 *   asks to be mailed goes through `sendMfaMail` (`mail.mts`), to the
 *   login's address, and the digest of that address is kept with the pending
 *   challenge and handed back to the verification. The page is answered the
 *   factor's response with where the code went, masked (`sent_to`), and how
 *   long it lives (`expires_in`), as kept.
 * - What a record can do is `factorState.mts`'s one reading: what a
 *   transaction offers (`isOffered`) and what is usable are that file's.
 * - A refusal carries the factor id the factor named only when it is one of
 *   the subject's factors of the kind verified: nothing else reaches the audit.
 *   Another is dropped and flagged, never quoted.
 * - A factor's answer — a challenge's, a verification's — is read once, field
 *   by field, however the factor holds it (a getter, a class's instance), and
 *   only what was read is used. The state, data and response in it are taken
 *   as their plain copy (`copyFactorValue`) where the answer is read, and that
 *   one copy is what `amrFor`, the recovery-code rules, the seal and the page
 *   act on; one that is not plain JSON-shaped is the factor's failure
 *   (`503`), the stored data left as it was. A mail it asks for is read there
 *   too (`copyAskedMail`). A verification is a success only when its `ok` is
 *   `true` and a refusal only when it is `false` with a reason its type
 *   names: anything else is the factor's failure. What `amrFor` answers is
 *   copied once, and only the copy is checked and used.
 * - A factor's `identity` is read as a non-empty string or none; one that
 *   throws is none — the record a duplicate of none — and is said through
 *   `identityFailed`.
 */
import { type MailSender, type MfaFactorResolver, type MfaFactorStore, type MfaTransactionStore, type SubjectRevocation } from "@o3co/auth-provider-core";
import { type MfaCeremonyCall, type MfaChallengeOutcome, type MfaDescribeOutcome, type MfaEnrollmentBeginOutcome, type MfaEnrollmentCompleteOutcome, type MfaStepUpOutcome, type MfaVerifyOutcome } from "./ceremony.mjs";
import type { MfaFactorSet } from "./factorSet.mjs";
import type { RequireEmailProof } from "./firstBinding.mjs";
import { type FirstBindingMark } from "./firstBindingMark.mjs";
import { type MfaSubjectLock } from "./lock.mjs";
import type { MfaRequirementMode } from "./requirement.mjs";
import { type MfaSealing } from "./sealing.mjs";
import { type MfaEnrollmentWitness } from "./witness.mjs";
export interface MfaCoordinator {
    describe(call: MfaCeremonyCall): Promise<MfaDescribeOutcome>;
    challenge(call: MfaCeremonyCall & {
        readonly factorId: unknown;
    }): Promise<MfaChallengeOutcome>;
    verify(call: MfaCeremonyCall & {
        readonly factorId: unknown;
        readonly proof: unknown;
    }): Promise<MfaVerifyOutcome>;
    /** An enrollment begun — a login's first binding, or one in the session `call.session` names — the factor of `kind` started (`enrollment.mts`). */
    beginEnrollment(call: MfaCeremonyCall & {
        readonly kind: unknown;
    }): Promise<MfaEnrollmentBeginOutcome>;
    /** An enrollment completed: the proof taken, the factor bound (`enrollment.mts`). */
    completeEnrollment(call: MfaCeremonyCall & {
        readonly proof: unknown;
        readonly label: unknown;
    }): Promise<MfaEnrollmentCompleteOutcome>;
    /**
     * The step-up of `call.session`'s subject (`stepUp.mts`): with no record
     * that may count, the `enroll` transaction the account-email proof is
     * owed on; holding one, the `step_up` transaction its factor is verified
     * on, recording `acrValues` — each the one `call` names when it is that
     * session's own and still usable, else a new one.
     */
    stepUp(call: MfaCeremonyCall & {
        readonly acrValues: readonly string[] | undefined;
    }): Promise<MfaStepUpOutcome>;
}
export interface MfaCoordinatorOptions {
    readonly factors: MfaFactorResolver;
    readonly factorStore: Pick<MfaFactorStore, "update">;
    readonly transactions: MfaTransactionStore;
    readonly sealing: MfaSealing;
    /** `mfa.maxAttemptsPerTransaction`. */
    readonly maxAttemptsPerTransaction: number;
    /** The subject lock a verification's proof is held to. */
    readonly lock: MfaSubjectLock;
    /** `mfa.mode`: under `required` a factor that does not count completes no login for a subject with no counting factor it can use. */
    readonly mode: MfaRequirementMode;
    /** Where a factor's codes are mailed; none wired, a factor that asks for one is an outage. */
    readonly mailSender?: MailSender;
    /** The enrollment witness a verified counting factor reconciles. */
    readonly witness: MfaEnrollmentWitness;
    /** The subject's records as read, the witness's reconciliation mark, and an enrollment's writes under the subject's lease (`factorSet.mts`). */
    readonly factorSet: MfaFactorSet;
    /** `mfa.transactionTtlSeconds`: how long an `enroll` transaction lives. */
    readonly transactionTtlSeconds: number;
    /** `mfa.maxFactorsPerSubject`. */
    readonly maxFactorsPerSubject: number;
    /** `mfa.enrollment.requireEmailProof`: the gate of a login reopened for a first binding. */
    readonly requireEmailProof: RequireEmailProof;
    /** `mfa.manage.maxAgeSeconds`: how long the account-email proof given in a session stands. */
    readonly sessionProofSeconds: number;
    /** The first-binding mark as every reader judges it (`createFirstBindingMark`). */
    readonly firstBindingMark: FirstBindingMark;
    /** The subjects' sessions boundary a login's transaction is held to; none wired, none is read. */
    readonly subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
    /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
    readonly now?: () => number;
    /** Where a factor's `identity` that threw is said; the record is judged a duplicate of none. */
    readonly identityFailed?: (kind: string, cause: unknown) => void;
}
/** The coordinator over `options` (see this file's header). */
export declare function createMfaCoordinator(options: MfaCoordinatorOptions): MfaCoordinator;
//# sourceMappingURL=coordinator.d.mts.map