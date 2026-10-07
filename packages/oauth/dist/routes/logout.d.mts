import type { AuditSinkBase, ClientRepository, FederationProviderHandle, FederationTokenStoreBase, KeyStore, Logger, RefreshTokenStoreBase, UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface LogoutRouterOptions {
    keyStore: KeyStore;
    /** Issuer URL of this auth provider — used for logout_token `iss` claim and iframe `iss` param. */
    issuer: string;
    userSessionStore: UserSessionStoreBase;
    federationTokenStore: FederationTokenStoreBase;
    refreshTokenStore: RefreshTokenStoreBase;
    clientRepository: ClientRepository;
    /**
     * Getter for the federation providers Map. Evaluated at request time (not at
     * router construction time) so module init order does not matter — Task 6b
     * will pass `() => context.federationProviders` rather than a captured Map
     * reference. Returns undefined when federation is not configured.
     */
    getFederationProviders: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
    /** Override for unit tests. Defaults to the global `fetch`. */
    fetchImpl?: typeof fetch;
    /** Structured logger shared with broadcastBackchannelLogout and cascadeLogout. */
    logger?: Logger;
    /** Audit sink for operator observability events. No-op when undefined. */
    auditSink?: AuditSinkBase;
}
/**
 * OIDC RP-Initiated Logout 1.0 — POST /oauth/logout
 *
 * Accepts application/x-www-form-urlencoded with:
 *   - id_token_hint (required)
 *   - post_logout_redirect_uri (optional)
 *   - state (optional)
 *
 * Flow:
 *   1. Verify id_token_hint via keyStore. Fail → 400 invalid_token.
 *   2. Extract `sid` and `aud` (= client_id). Missing sid → 400 invalid_request.
 *   3. Load session from userSessionStore. Missing → 200 JSON { logged_out: true } (no-op).
 *   4. Broadcast Back-Channel Logout to all registered RPs (best-effort).
 *   5. Resolve IdP end-session URI for the first federation (if any, if provider supportsEndSession).
 *   6. Cascade logout (revokeFamily + deleteBySession + delete session).
 *   7. Respond: front-channel HTML | IdP redirect | post-logout redirect | 200 JSON.
 *
 * /oauth/federation/:name/logout is handled in Task 6b (not this file).
 */
export declare function createRouter(express: ExpressLike, opts: LogoutRouterOptions): Router;
export {};
//# sourceMappingURL=logout.d.mts.map