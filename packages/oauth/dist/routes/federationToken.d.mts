import type { AuditSinkBase, ClientRepository, FederationProviderHandle, FederationTokenStoreBase, KeyStore, Logger, RefreshTokenStoreBase, UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface FederationTokenRouterOptions {
    keyStore: KeyStore;
    refreshTokenStore: RefreshTokenStoreBase;
    userSessionStore: UserSessionStoreBase;
    federationTokenStore: FederationTokenStoreBase;
    clientRepository: ClientRepository;
    /**
     * Getter for the federation providers Map. Evaluated at request time (not at
     * router construction time) so module init order does not matter.
     * Returns undefined when federation is not configured.
     */
    getFederationProviders: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
    /** Audit sink for operator observability events. No-op when undefined. */
    auditSink?: AuditSinkBase;
    /** Structured logger. Defaults to console when undefined. */
    logger?: Logger;
    /**
     * Tokens within this many milliseconds of expiry are proactively refreshed.
     * Default: 30_000 (30 seconds).
     */
    refreshBufferMs?: number;
}
/**
 * POST /federation/:name/token — Federation token proxy endpoint (TODO-F-6).
 *
 * Allows opt-in clients to retrieve the user's upstream federation access_token.
 * The caller must present a valid at+jwt access token in the Authorization header.
 * The client identified by `azp` must have `allowedAzpForFederationToken: true`.
 *
 * Mounted under /oauth → POST /oauth/federation/:name/token.
 */
export declare function createRouter(express: ExpressLike, opts: FederationTokenRouterOptions): Router;
export {};
//# sourceMappingURL=federationToken.d.mts.map