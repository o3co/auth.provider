/**
 * Callback check 5: whether the upstream account the exchange verified may be bound
 * to this grant, and what the grant's event records of the answer. An answer the
 * port does not define, or one that establishes neither this user nor nobody,
 * refuses.
 */
import type { FederationGrantAcquisitionConnection, FederationGrantIntent } from "@o3co/auth-provider-core";
import type { CallbackError } from "./browserAnswers.mjs";
import type { BrowserFlow, Unanswered } from "./browserFlow.mjs";
/**
 * Check 5. The verified issuer is the connection's; a renewal's upstream account
 * is the one already on the grant; an expectation the client lodged is met; and,
 * unless the deployment recorded that it cannot ask, the Store establishes who
 * holds the upstream account: this user or nobody. Another user is a conflict.
 * An answer that establishes neither also refuses: "cannot tell" is not "linked
 * to nobody", and reading it so would let a pairwise `sub` through.
 */
export declare function accountHolds({ options, now }: BrowserFlow, intent: FederationGrantIntent, connection: FederationGrantAcquisitionConnection, upstream: {
    readonly issuer: string;
    readonly subject: string;
    readonly claims?: unknown;
}): Promise<AccountBinding>;
/**
 * Check 5's verdict. When it holds, `outcome` is what the grant's event
 * records: which answer let it through, or that the deployment does not ask.
 */
export type AccountBinding = {
    readonly holds: true;
    readonly outcome: "required/linked" | "required/unlinked" | "unsupported";
} | {
    readonly holds: false;
    readonly code: CallbackError;
    readonly reason?: string;
    /** When nothing could be established: what could not answer, for the one line. */
    readonly unanswered?: Unanswered;
};
//# sourceMappingURL=browserAccountBinding.d.mts.map