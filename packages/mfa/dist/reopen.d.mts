/**
 * A login reopened for a binding (the MFA ADR's F3, D12, D24, D25), over the
 * coordinator's kit: under `required`, a proof that does not count, verified
 * for a subject left with no counting factor it can use, completes no login.
 * The verification consumes the transaction and spends the proof; then a new
 * login transaction is opened over the same continuation, bound to the same
 * browser session, for:
 *
 * - `allowed` beside a record that may count (`reopenedEnrollment`): bound by
 *   `mfa`, no proof asked, no codes issued;
 * - `required` otherwise, a first binding: the login's `User` must not say
 *   the subject enrolled, and the one gate (`firstBindingGate`) decides the
 *   proof over the continuation's address fact — core's
 *   `enrollmentFactsOfContinuation`, as read at the sign-in — and D25's flag.
 *
 * What it is opened for is settled before anything is spent (`plan`, called
 * before the transaction's attempt is reserved), so a refusal or an outage
 * there spends neither the transaction, nor an attempt, nor the proof: a
 * first binding's witness; the counting factors the user may enroll — none,
 * or one that cannot say, is an outage; D25's flag and the gate — a proof
 * nobody can give is refused; and `mfa.maxFactorsPerSubject` — for a first
 * binding, its factor and its codes, less a set they replace. A first
 * binding whose continuation the subject's first-binding mark distrusts
 * (`firstBindingMark.mts`) is refused too; a mark that cannot be read is an
 * outage.
 */
import { type InterruptionAnswer, type MfaFactorRecord, type MfaTransaction } from "@o3co/auth-provider-core";
import { type MfaCeremonyKit, type MfaReopenRefusal, type MfaStoreOutage } from "./ceremony.mjs";
/** What a login is reopened for, settled before the proof is spent. */
export interface MfaReopenPlan {
    readonly enrollment: "allowed" | "required";
    readonly enrollable: readonly string[];
    /** Whether the account-email proof comes first: a first binding's, as the gate asked. */
    readonly emailProof: boolean;
}
/** The login's reopening over the coordinator's `kit` (see this file's header). */
export declare function createLoginReopen(kit: MfaCeremonyKit): {
    /** What `tx`'s login reopens for over the subject's `records`; why not, or the outage. */
    plan(tx: MfaTransaction, records: readonly MfaFactorRecord[]): Promise<MfaReopenPlan | MfaReopenRefusal | MfaStoreOutage>;
    /** The new transaction `plan` settled, over `consumed`'s continuation and binding: the login's `403`, or the outage. */
    open(consumed: MfaTransaction, plan: MfaReopenPlan): Promise<InterruptionAnswer | MfaStoreOutage>;
};
//# sourceMappingURL=reopen.d.mts.map