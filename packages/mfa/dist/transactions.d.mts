import type { InterruptionAnswer, MfaTransaction, MfaTransactionBinding, MfaTransactionStore, PrimaryContinuation } from "@o3co/auth-provider-core";
/** The shortest and the longest a transaction may live, in seconds. */
export declare const MFA_TRANSACTION_TTL_SECONDS: {
    readonly min: 60;
    readonly max: 1800;
};
/** What the login is interrupted for: a second factor, or a first binding with what it may bind. */
export type LoginInterruption = {
    readonly error: "mfa_required";
} | {
    readonly error: "mfa_enrollment_required";
    /** The kinds this user may enroll, in registration order: `hints.enrollable`. */
    readonly enrollable: readonly string[];
    /**
     * Whether the account-email proof comes before the binding
     * (`firstBinding.mts`): `hints.email_proof`, and the transaction's
     * `emailProof` — `required` or `not_required` — so the answer
     * advertises exactly the proof the transaction enforces.
     */
    readonly emailProof: boolean;
};
/** Opens a login's transaction and answers the interruption. */
export interface LoginTransactions {
    /**
     * Creates the `login` transaction bound to the session `sessionId` names
     * (`{ kind: "session", id: sessionId }`), carrying `continuation`, and
     * answers the closed 403 body. Rejects when the store cannot keep it.
     */
    open(sessionId: string, continuation: PrimaryContinuation, interruption: LoginInterruption): Promise<InterruptionAnswer>;
}
export interface LoginTransactionsOptions {
    readonly store: MfaTransactionStore;
    /** `mfa.transactionTtlSeconds`: a whole number of seconds, 60 to 1800. */
    readonly ttlSeconds: number;
    /** The clock, in epoch milliseconds. Defaults to `Date.now`; a test seam. */
    readonly now?: () => number;
}
/**
 * The login's transactions over `store`, each living `ttlSeconds` — refused
 * with a `RangeError` when it is not a whole number from 60 to 1800.
 */
export declare function createLoginTransactions({ store, ttlSeconds, now, }: LoginTransactionsOptions): LoginTransactions;
/** What a login is reopened for after a non-counting proof. */
export interface LoginBindingShape {
    /** What the login's transaction was bound to, whole. */
    readonly binding: MfaTransactionBinding;
    readonly continuation: PrimaryContinuation;
    /** `allowed`: a binding beside a record that may count; `required`: a first binding. */
    readonly enrollment: "allowed" | "required";
    /** The counting factors the user may enroll: `hints.enrollable`. */
    readonly enrollable: readonly string[];
    /** Whether the account-email proof comes first: the gate's, for a first binding alone. */
    readonly emailProof: boolean;
    readonly nowMs: number;
    /** `mfa.transactionTtlSeconds`. */
    readonly ttlSeconds: number;
}
/**
 * Creates the login transaction `shape` reopens in `store` and answers the
 * login's `403 mfa_enrollment_required` naming it. A proof owed beside a
 * record that may count is a `RangeError`, before anything is stored; a
 * store that cannot keep it rejects.
 */
export declare function openLoginBinding(store: MfaTransactionStore, shape: LoginBindingShape): Promise<InterruptionAnswer>;
/** What an `enroll` transaction is opened for. */
export interface EnrollTransactionShape {
    /** The express session id of the browser that opened it. */
    readonly sessionId: string;
    /** The `UserSession` it was opened in, and its subject. */
    readonly sid: string;
    readonly subject: string;
    /** `required`: the subject's first counting factor; `allowed`: one beside a factor that may count. */
    readonly enrollment: "required" | "allowed";
    /** Whether the account-email proof is owed on it. */
    readonly emailProof: "required" | "not_required";
    readonly nowMs: number;
    /** `mfa.transactionTtlSeconds`. */
    readonly ttlSeconds: number;
}
/** What a signed-in session's step-up transaction is opened for. */
export interface StepUpTransactionShape {
    /** The express session id of the browser that opened it. */
    readonly sessionId: string;
    /** The `UserSession` it steps up, and its subject. */
    readonly sid: string;
    readonly subject: string;
    /** The `acr_values` the page hinted, read; `undefined` for none. */
    readonly acrValues: readonly string[] | undefined;
    readonly nowMs: number;
    /** `mfa.transactionTtlSeconds`. */
    readonly ttlSeconds: number;
}
/**
 * Creates a new `enroll` transaction for `shape` in `store` — a fresh id, no
 * continuation, bound to the session `sessionId` names — and answers it.
 * Rejects when the store cannot keep it.
 */
export declare function openEnrollTransaction(store: MfaTransactionStore, shape: EnrollTransactionShape): Promise<MfaTransaction>;
/**
 * Creates a new `step_up` transaction for `shape` in `store` — a fresh id, no
 * continuation, bound to the session `sessionId` names, verifying a factor
 * the subject holds and owing no proof — and answers it. Rejects when the
 * store cannot keep it.
 */
export declare function openStepUpTransaction(store: MfaTransactionStore, shape: StepUpTransactionShape): Promise<MfaTransaction>;
//# sourceMappingURL=transactions.d.mts.map