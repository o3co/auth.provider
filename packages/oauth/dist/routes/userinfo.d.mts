import { type KeyStore, type RefreshTokenStoreBase, type UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface UserinfoRouterOptions {
    keyStore: KeyStore;
    userSessionStore?: UserSessionStoreBase;
    refreshTokenStore?: RefreshTokenStoreBase;
}
/**
 * OIDC Core §5.3 — UserInfo Endpoint.
 *
 * Accepts Bearer access_token JWTs and returns scope-filtered claims from
 * the durable UserSession. Revocation is checked via family_id (cascade
 * revoke per F-3) and sid (session liveness).
 *
 * Error responses follow Bearer Token Usage (RFC 6750 §3.1): 401 with
 * WWW-Authenticate header. Fail-closed on store errors.
 */
export declare function createRouter(express: ExpressLike, opts: UserinfoRouterOptions): Router;
export {};
//# sourceMappingURL=userinfo.d.mts.map