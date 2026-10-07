/**
 * The presented tokens: each token type backed by a validator, the subject and the
 * actor validated, and each held to the sender constraint this request proves. A
 * validator that cannot reach an answer is a `503`, never a verdict on the token;
 * one whose answer names a family or a session other than as a string is a failed
 * validation.
 */
import { type Confirmation, type ExchangeTokenValidator, type GrantContext, type GrantDependencies, type GrantHandlerResult, type TokenExchangeValidatorResolver, type ValidatedToken } from "@o3co/auth-provider-core";
import type { TokenRequest } from "./tokenRequest.mjs";
/** The validator for each presented token, and the issued token type, checked. */
export declare function resolveValidators(tokenExchangeValidatorResolver: Pick<TokenExchangeValidatorResolver, "get">, { subjectTokenType, actorToken, actorTokenType, requestedTokenType, }: Pick<TokenRequest, "subjectTokenType" | "actorToken" | "actorTokenType" | "requestedTokenType">): {
    readonly subjectValidator: ExchangeTokenValidator;
    readonly actorValidator: ExchangeTokenValidator | null | undefined;
} | GrantHandlerResult;
/** The subject token, validated and held to the sender constraint; and what the issued token is bound to. */
export declare function validateSubject(deps: Pick<GrantDependencies, "logger">, ctx: GrantContext, { subjectToken }: Pick<TokenRequest, "subjectToken">, subjectValidator: ExchangeTokenValidator): Promise<{
    readonly subjectValidated: ValidatedToken;
    readonly subjectBindings: ReportedBindings;
    readonly issuedConfirmation: Confirmation | undefined;
} | GrantHandlerResult>;
/** The actor token, when one was sent, validated and held to the sender constraint; else `null`. */
export declare function validateActor(deps: Pick<GrantDependencies, "logger">, ctx: GrantContext, { actorToken }: Pick<TokenRequest, "actorToken">, actorValidator: ExchangeTokenValidator | null | undefined): Promise<{
    readonly actorValidated: ValidatedToken | null;
    /** The actor's bindings; `null` with no actor. */
    readonly actorBindings: ReportedBindings | null;
} | GrantHandlerResult>;
/**
 * The presented token's validator asked again, answered as the first asking
 * was: `null` when it still accepts the token, else the same refusal or `503`.
 * Its answer gates only; the bindings and claims read at the first asking stay
 * the ones checked and minted.
 */
export declare function revalidate(deps: Pick<GrantDependencies, "logger">, role: "subject" | "actor", token: string, validator: ExchangeTokenValidator): Promise<GrantHandlerResult | null>;
/**
 * The family and the session a validator reports, each read once off its
 * answer: a non-empty string, or `undefined` for unset (an empty string
 * included, so no token inherits a `family_id: ""` that no revocation could
 * reach). The family rule, the session rule and issuance read these, never
 * the answer again.
 */
export interface ReportedBindings {
    readonly familyId: string | undefined;
    readonly sid: string | undefined;
}
//# sourceMappingURL=tokenValidation.d.mts.map