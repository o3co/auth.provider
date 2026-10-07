/**
 * Reading and checking the token request: each parameter read once, a repeated or
 * malformed value refused rather than ignored or reinterpreted, and the effective
 * client id the body's, else the authenticated client's.
 */
import type { GrantContext, GrantHandlerResult } from "@o3co/auth-provider-core";
/** The token request as read. */
export interface TokenRequest {
    readonly body: Record<string, unknown>;
    readonly subjectToken: string;
    readonly subjectTokenType: string;
    readonly bodyClientId: string | null;
    readonly clientId: string;
    readonly clientSecret: string | null;
    readonly requestedExpiresIn: number | undefined;
    readonly actorToken: string | null;
    readonly actorTokenType: string | null;
    readonly requestedTokenType: string | null;
}
export declare function readTokenRequest(ctx: GrantContext): TokenRequest | GrantHandlerResult;
//# sourceMappingURL=tokenRequest.d.mts.map