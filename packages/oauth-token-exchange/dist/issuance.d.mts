/**
 * The token mint: the issued access token's `act`, scope, audience and binding, and
 * its lifetime, the requested or the default one clamped to the maximum and never
 * past the subject token's own expiry. A subject token that has already expired is
 * refused, never minted from. The subject's `acr`, `amr` and `auth_time` are carried
 * only from a token this provider's own validator verified for the issuer minting;
 * the actor's never are.
 */
import { type AccessTokenLifetime, type Confirmation, type GrantContext, type GrantDependencies, type GrantHandlerResult, type PublicClient, type Token, type ValidatedToken } from "@o3co/auth-provider-core";
import type { ReportedBindings } from "./tokenValidation.mjs";
/** What the issued token is minted from. */
export interface Issuance {
    /** The issuance instant, epoch seconds: the minted `iat`, and what `exp` is measured from. */
    readonly issuedAt: number;
    readonly client: PublicClient;
    readonly subjectValidated: ValidatedToken;
    /** The subject's family and session, as read once at validation. */
    readonly subjectBindings: ReportedBindings;
    readonly actorValidated: ValidatedToken | null;
    readonly grantedScope: readonly string[] | undefined;
    readonly audienceForToken: string;
    readonly requestedExpiresIn: number | undefined;
    readonly issuedConfirmation: Confirmation | undefined;
}
export declare function issueAccessToken(deps: Pick<GrantDependencies, "keyStore" | "logger">, ctx: GrantContext, { defaultExpiresIn, maxExpiresIn }: AccessTokenLifetime, { issuedAt, client, subjectValidated, subjectBindings, actorValidated, grantedScope, audienceForToken, requestedExpiresIn, issuedConfirmation, }: Issuance): Promise<{
    readonly accessToken: Token;
    /** Seconds left of the lifetime when it was signed: the answer's `expires_in`. */
    readonly expiresIn: number;
} | GrantHandlerResult>;
//# sourceMappingURL=issuance.d.mts.map