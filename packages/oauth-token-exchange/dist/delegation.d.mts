/**
 * Who may act for the subject: an actor whose token names the calling client, as the
 * subject token must, and whom the subject token's `may_act` names, within the
 * deepest actor chain allowed; with no actor token, the calling client under the
 * same `may_act`, so omitting the actor cannot opt out of it. A refusal is
 * `invalid_request` with one warn line.
 */
import type { GrantDependencies, GrantHandlerResult, PublicClient, ValidatedToken } from "@o3co/auth-provider-core";
/** What delegation reads: the logger, and the module's section for the chain depth. */
type DelegationDependencies = Pick<GrantDependencies, "logger"> & {
    readonly section?: {
        readonly maxActorChainDepth?: number;
    };
};
/** The delegation's refusal, or `null` when the actor, or the client, may act. */
export declare function delegationRefusal(deps: DelegationDependencies, client: PublicClient, subjectValidated: ValidatedToken, actorValidated: ValidatedToken | null): GrantHandlerResult | null;
export {};
//# sourceMappingURL=delegation.d.mts.map