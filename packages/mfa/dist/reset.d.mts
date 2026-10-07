/**
 * The operator reset, `resetMfaForSubject`: for a subject who lost their
 * second factors, an identity the operator verified out of band.
 *
 * - Refused with a `RangeError`, nothing done, for a subject that is not a
 *   non-empty string, a federation-grant disposition other than `revoke` or
 *   `keep`, a `requestedBy` that is not a well-formed string of 1 to 256
 *   characters, or `requireEmailProof` with no mail sender wired — nobody
 *   could give the proof, so nobody could bind. A Store must also not ask it
 *   for an account with no address.
 * - Then, in this order: every session and token of the subject's ended
 *   (`revokeAllForSubject`, the federation grants as asked) — a revocation
 *   that throws or is not complete stops it, nothing more done; then, under
 *   one lease of the subject's, waited for (`factorSet.mts`), each write held
 *   to the lease's time: D25's flag set when asked — under the lease, so no
 *   binding that held it before can clear it — the reset's own one-time
 *   authorization recorded (`lockRecovery.mts`) and applied: the lock state
 *   reset whole — the hard hold, every authorization of the subject's, and
 *   the generation moved on, so a factor-set write begun before stops at its
 *   commit — then every record removed (`removeAllForSubject`: one sealed
 *   under a retired key, of a kind not installed, or a recovery-code set
 *   alike), and the witness cleared last; and, once the lease part is done,
 *   every session and token ended again: a login made with a factor before
 *   its removal ends too.
 * - Answers a report: whether it completed — both revocations complete, the
 *   lease held throughout — where it stopped, both sessions' reports, the
 *   kinds and count of the records removed (once the removal succeeded), the
 *   generation, the witness. It is idempotent: run again, it does it all
 *   again. Emits one `mfa.reset`, and no `mfa.lock.recovered`.
 * - Residual: a write admitted before the revocation that ran past its lease
 *   can land after the removal; the factor-set's lease is logical.
 */
import { type AuditSink, type FederationGrantDisposition, type Logger, type MfaFactorStore, type MfaTransactionStore, type SubjectRevocationReport, type SubjectRevocationService, type UserRepository } from "@o3co/auth-provider-core";
import { type MfaSubjectLeases } from "./factorSet.mjs";
/** What the operator asks of a reset. */
export interface MfaResetRequest {
    /** D25: the subject's next first binding requires the account-email proof. */
    readonly requireEmailProof?: boolean;
    /** What becomes of the subject's federation grants; `revoke` when not given, and policy decides a `keep`. */
    readonly federationGrants?: FederationGrantDisposition;
    /** Who asked, as the operator's records name it: audited, never read. */
    readonly requestedBy?: string;
}
/** Where a reset stopped. */
export type MfaResetStop = "email_proof" | "sessions" | "lease" | "lock" | "factors" | "witness";
/** What a reset did. */
export interface MfaResetReport {
    readonly subject: string;
    /** Every step done under a lease held throughout: the sessions ended twice, the lock state reset, every record removed, the witness cleared or not writable here. */
    readonly complete: boolean;
    /** Where it stopped, when a step did not complete: run it again. One whose lease ended before its release says `overran` alone. */
    readonly stoppedAt?: MfaResetStop;
    /** Why it stopped there. */
    readonly cause?: unknown;
    readonly requireEmailProof: boolean;
    /** What the revocation reported; none when it stopped before, or the revocation threw. */
    readonly sessions?: SubjectRevocationReport;
    /** What the revocation once the lease part was done reported; none when it did not run, or threw. */
    readonly sessionsAgain?: SubjectRevocationReport;
    /** Once the removal succeeded: the kinds, each once in code-unit order, and the count of the records removed, as read just before; none when they could not be read. */
    readonly removed?: {
        readonly kinds: readonly string[];
        readonly count: number;
    };
    /** The subject's generation once the lock state was reset. */
    readonly generation?: number;
    /** `cleared`, or `unwritable` when the directory cannot write the witness. */
    readonly witness?: "cleared" | "unwritable";
    /** The lease ended before the reset released it: another writer may have run beside it. */
    readonly overran?: true;
}
export interface MfaReset {
    /** The operator reset of `subject` (see this file's header). */
    resetMfaForSubject(subject: string, request?: MfaResetRequest): Promise<MfaResetReport>;
}
export interface MfaResetOptions {
    readonly factorStore: MfaFactorStore;
    readonly transactionStore: MfaTransactionStore;
    readonly subjectRevocationService: SubjectRevocationService;
    /** The directory the witness is cleared through; none, or one without `markMfaEnrolled`, clears nothing. */
    readonly userRepository?: UserRepository;
    /** Whether a mail sender is wired: `requireEmailProof` needs one. */
    readonly mailWired: boolean;
    /** A lease owner of the rules every writer of a subject's factor set holds (`mfaModule`'s `mfaSubjectLeases`). */
    readonly leases: MfaSubjectLeases;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
    /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
    readonly now?: () => number;
}
/** The operator reset over `options` (see this file's header). */
export declare function createMfaReset(options: MfaResetOptions): MfaReset;
//# sourceMappingURL=reset.d.mts.map