/**
 * The client (RFC 6749 §4.1.1): `client_id`, the `redirect_uri` allowlist and
 * what the registration permits here. Until `redirect_uri` is validated no
 * redirect target is trusted, so identification answers 400/503 JSON.
 */
import { type PublicClient } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { type AuthorizeContext, type AuthorizeHandlerOptions } from "./authorizeContext.mjs";
/**
 * RFC 6749 §4.1.1 identification: `client_id`/`redirect_uri` presence, client
 * lookup and the `redirect_uri` allowlist, then core's `checkRedirectUri` on
 * the presented URI. Everything here answers 400/503 JSON because no trusted
 * redirect target exists yet. A malformed `client_id` is answered as unknown
 * and never reaches the repository (which may throw on it); a repository that
 * throws is `503 temporarily_unavailable`.
 *
 * Returns `null` when a response has been sent.
 */
export declare const resolveClientAndRedirectUri: (req: Request, res: Response, opts: AuthorizeHandlerOptions) => Promise<{
    client: PublicClient;
    clientId: string;
    redirectUri: string;
} | null>;
export declare const checkAuthorizationCodeGrantAllowed: (ctx: AuthorizeContext, client: PublicClient) => Promise<boolean>;
export declare const checkFirstPartyOrConsentable: (ctx: AuthorizeContext, client: PublicClient) => Promise<boolean>;
//# sourceMappingURL=authorizeClient.d.mts.map