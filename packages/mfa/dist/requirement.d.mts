/**
 * The `mfa` session requirement: what MFA means to every consumer of a session,
 * through core's admission, reached through `sessionRequirements.mfa` only. It
 * declares the second-factor authority; the name `mfa` is this package's own.
 *
 * `reach` (the enabled factors' `amrValues`, plus `mfa` when one `addsMfa`) is
 * read once, after every factor has registered, and kept: boot refuses it unless
 * it equals what core recomputes from the same factors, and the requirement's own
 * verdicts read the same snapshot, so the two never disagree.
 *
 * `admit` decides by the mode and the action's grade, never its name
 * (`RECORD_RULES`). A token is judged on its own `amr` (`admitToken`) under
 * `required`, whatever the grade, and met under `optional`. A session a cookie,
 * code or link carries is held, under `required`, to its record's baseline,
 * except that an action graded `grants_nothing` is met on any live record;
 * under `optional` it is met. The baseline steps a password session without a
 * second factor up only when its subject may hold a counting factor to step
 * up with; without one it sends the session to log in, where the login's
 * first binding is made. A second factor's step-up is answered only where
 * admission's view says one can be recorded on the session
 * (`SessionView.secondFactorRecordable`, decided by core over the store and
 * the record); elsewhere the session is sent to log in, where the login
 * records it. An action graded `credential_change` changes the
 * ways into the account — adds one, or renames or removes a factor — and is
 * held to recent MFA (`isRecentMfa`: a second factor verified lately, in a
 * session whose vouched `amr` holds `mfa`; a session without it is stepped
 * up only toward a record that can add it, `unmet` otherwise) over a primary the
 * baseline knows — under `required` on top of the baseline, so it is never
 * looser than `use`: the subject's factor records say whether it may hold a
 * counting factor — a record of a kind no installed factor declares
 * non-counting counts — and a list that cannot answer throws.
 *
 * For a subject that holds none, the action is a first binding (D12, D24):
 * the view's recorded facts are read — none recorded sends the session to
 * log in; a witness `enrolled` or malformed sends a password session to log
 * in, whose own read of the `User` records a real loss, and is recorded and
 * thrown for any other primary, a federated login having no such read —
 * then a recent primary (core's `authenticationFreshness`: `authTime`, or for
 * a federated login the earlier of that and the upstream's recorded
 * authentication once the federation callback records it, never recent when
 * the upstream showed no time; a second factor does not stand in for it), then the subject's first-binding mark
 * (`firstBindingMark.mts`), read against when the session was established: a
 * session it distrusts, whose recorded witness may predate the subject's
 * enrollment, is sent to log in — said at info — and a mark that cannot be
 * read throws;
 * then the one gate, whose proof is the one given in that session and
 * still standing (`MfaTransactionStore.sessionEmailProofAt`, read no older
 * than `mfa.manage.maxAgeSeconds` and the clock skew). A proof nobody can
 * give steps the session up and never admits it.
 *
 * `admitPrimary` interrupts a password login for a second factor when the subject
 * holds a record it asks for one over (`factorState.mts`): a record it cannot use is
 * never "none", a recovery set with no code left is, and a `list` that cannot
 * answer throws, which admission answers `unavailable`. When no
 * record that may count stands, the login's `User` must not say the subject
 * enrolled: a witness `true` or malformed is recorded and thrown, under either
 * mode (D12). With none it asks over, `optional` establishes and `required` interrupts
 * for a first binding offering the counting factors the user may enroll, the
 * account-email proof first where the one gate (`firstBinding.mts`) asks for
 * it. Other primaries establish without a read: the baseline applies after
 * `pwd` only.
 *
 * Every method is a closure: core calls them on a registered copy, and the
 * contract suite on a spread of the object.
 */
import { type AuditSink, type Logger, type MfaFactorResolver, type MfaFactorStore, type SessionRequirement, type StepUpPage } from "@o3co/auth-provider-core";
import { type RequireEmailProof } from "./firstBinding.mjs";
import { type FirstBindingMark } from "./firstBindingMark.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { LoginTransactions } from "./transactions.mjs";
/** The name the requirement is registered under: `sessionRequirements.mfa`. */
export declare const MFA_REQUIREMENT_NAME = "mfa";
/** The two modes the requirement is registered under: `off` is refused by the module. */
export type MfaRequirementMode = "optional" | "required";
export interface MfaRequirementOptions {
    readonly mode: MfaRequirementMode;
    /** The installed factors, read when asked: they register in the same pass as the requirement. */
    readonly factors: MfaFactorResolver;
    readonly factorStore: Pick<MfaFactorStore, "list">;
    readonly transactions: LoginTransactions;
    /** `mfa.page.url`, as the page a step-up starts on. */
    readonly stepUpPage: StepUpPage;
    /** `mfa.manage.maxAgeSeconds`: how long a second factor verified in a session stays recent. */
    readonly recentMfaMaxAgeSeconds: number;
    /** Where a first binding that offers nothing, or asks a proof nobody can give, is said. */
    readonly logger: Logger;
    /** Where `mfa.enrollment_state_inconsistent` is recorded; none, it is not. */
    readonly auditSink?: AuditSink;
    /** What the first-binding gate reads of the composition: `mfa.enrollment.requireEmailProof`, and whether a mail sender is wired. */
    readonly firstBinding: {
        readonly requireEmailProof: RequireEmailProof;
        readonly mailWired: boolean;
    };
    /** D25's flag for `subject` (`MfaTransactionStore.emailProofRequiredAtNextBinding`); rejects on an outage. */
    readonly emailProofRequiredAtNextBinding: (subject: string) => Promise<boolean>;
    /**
     * The subject's recovery-set floor, bounded by one Store timeout: a
     * password login asks for no second factor over a set below it; one that
     * cannot be read is said at warn and reads every set as without it.
     */
    readonly recoverySetFloor: (subject: string) => Promise<number>;
    /**
     * When the account-email proof was given in the session `sid` of
     * `subject`, while it stands at `nowMs` (`MfaTransactionStore.sessionEmailProofAt`);
     * rejects on an outage.
     */
    readonly sessionEmailProofAt: (subject: string, sid: string, nowMs: number) => Promise<number | null>;
    /**
     * When `subject`'s first-binding mark was noted, while it stands
     * (`MfaTransactionStore.firstBindingAt`); rejects on an outage.
     */
    readonly firstBindingAt: (subject: string, nowMs: number) => Promise<number | null>;
    /** The first-binding mark as every reader judges it (`createFirstBindingMark`). */
    readonly firstBindingMark: Pick<FirstBindingMark, "distrusts">;
    /** The key ring's sealing: what tells a recovery set with no code left (`factorState.mts`). */
    readonly sealing: MfaSealing;
}
/** What recent MFA is read from: a live session's primary time, its last second factor, and what it vouches for. */
export interface RecentMfaSession {
    readonly authTime: Date;
    readonly mfaAt: Date | undefined;
    /** Whether the session's vouched `amr` holds `mfa`: `mfaAt` counts only then. */
    readonly holdsMfa: boolean;
}
/** What recent MFA is told of the session's subject. */
export interface RecentMfaSubject {
    /**
     * Whether the subject holds a counting factor: without one, a recent
     * primary stands in for a second factor. Admission answers it with
     * `mayHoldCountingFactor`, which presumes a kind it cannot tell counts.
     */
    readonly holdsCountingFactor: boolean;
}
/**
 * Whether `session` has recent MFA at `nowMs`: a second factor verified
 * within `maxAgeSeconds` (`mfa.manage.maxAgeSeconds`) in a session whose
 * vouched `amr` holds `mfa` — an email code, which adds none by default,
 * does not give it to a session signed in with it — or, when `subject` holds
 * no counting factor, a primary that recent. The window's edge is recent.
 */
export declare function isRecentMfa(session: RecentMfaSession, subject: RecentMfaSubject, maxAgeSeconds: number, nowMs: number): boolean;
/** The `mfa` requirement over `options` (see this file's header). */
export declare function createMfaRequirement(options: MfaRequirementOptions): SessionRequirement;
//# sourceMappingURL=requirement.d.mts.map