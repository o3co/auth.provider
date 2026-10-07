/**
 * The scope and the targets a token exchange may name: the scope within the subject
 * token's and the client's `allowedScopes`, the audience within the client's
 * registration and the subject token's audience — requested, granted or defaulted —
 * and every resource equal to the audience the token is minted for. What the
 * request asks past them, or a default that lies past them, is refused.
 */
import { type GrantDependencies, type GrantHandlerResult, type PublicClient, type ValidatedToken } from "@o3co/auth-provider-core";
/** The request's scope and targets, each held to its ceilings, and the ceilings. */
export interface RequestTargets {
    readonly subjectScope: readonly string[];
    readonly subjectScopeSet: ReadonlySet<string>;
    readonly clientScopeSet: ReadonlySet<string>;
    readonly requestedScope: readonly string[] | null;
    readonly clientAudienceSet: ReadonlySet<string>;
    readonly subjectAudienceSet: ReadonlySet<string>;
    readonly requestedAudience: readonly string[] | null;
    readonly requestedResource: readonly string[] | null;
}
export declare function requestTargets(deps: Pick<GrantDependencies, "logger">, body: Record<string, unknown>, client: PublicClient, subjectValidated: ValidatedToken): RequestTargets | GrantHandlerResult;
/**
 * The audience the token is minted for, within both audience ceilings whether it was
 * requested, granted or defaulted, and every requested resource held equal to it.
 */
export declare function issuedTarget(deps: Pick<GrantDependencies, "logger">, client: PublicClient, subjectValidated: ValidatedToken, { clientAudienceSet, subjectAudienceSet, requestedResource, }: Pick<RequestTargets, "clientAudienceSet" | "subjectAudienceSet" | "requestedResource">, grantedAudience: readonly string[] | undefined): {
    readonly audienceForToken: string;
} | GrantHandlerResult;
//# sourceMappingURL=targetCeilings.d.mts.map