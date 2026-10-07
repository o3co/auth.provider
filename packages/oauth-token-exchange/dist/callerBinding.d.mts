/**
 * Whether the calling client may present the subject token, and the actor token:
 * by default only one that names it, by its `azp` or in its `aud`, unless the
 * client's registration sets `allowExchangeOfTokensIssuedToOthers`, which covers
 * both. A refusal is `invalid_request` with one warn line.
 */
import type { GrantDependencies, GrantHandlerResult, PublicClient, ValidatedToken } from "@o3co/auth-provider-core";
/**
 * The refusal, or `null` when the subject token names the client or the
 * registration lets the client exchange tokens issued to others. Reads the
 * validator's answer: its `aud`, and `azp` from its claims. A `client_id` claim
 * is not read: this provider stamps one only beside an `azp` of the same value.
 */
export declare function callerBindingRefusal(deps: Pick<GrantDependencies, "logger">, client: PublicClient, subjectValidated: ValidatedToken): GrantHandlerResult | null;
/**
 * The actor token's refusal on the subject token's terms, or `null` when the
 * actor token names the client or the registration lets the client exchange
 * tokens issued to others.
 */
export declare function actorCallerBindingRefusal(deps: Pick<GrantDependencies, "logger">, client: PublicClient, subjectValidated: ValidatedToken, actorValidated: ValidatedToken): GrantHandlerResult | null;
//# sourceMappingURL=callerBinding.d.mts.map