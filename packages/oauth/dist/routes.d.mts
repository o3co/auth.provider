import { type AppConfig, type AuditSinkBase, type ClientRepository, type CodeRepository, type FederationProviderHandle, type FederationTokenStoreBase, type GrantPolicyHookBase, type GrantRegistry, type KeyStore, type RateLimiterBase, type RefreshTokenStoreBase, type UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
declare module "express-session" {
    interface SessionData {
        client?: Record<string, unknown>;
        user?: Record<string, unknown>;
        code?: string;
        code_client_id?: string;
        code_redirect_uri?: string;
        granted_scopes?: string[];
        isAuthenticated?: boolean;
        /** UserSession ID — set by the federation callback hook or local login (`POST /session/login`) and preserved across session regeneration. */
        sid?: string;
    }
}
export declare const createOAuthRouter: (express: {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
}, { registry, config, clientRepository, codeRepository, keyStore, rateLimiter, auditSink, grantPolicy, refreshTokenStore, userSessionStore, federationTokenStore, getFederationProviders, }: {
    registry: GrantRegistry;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
    rateLimiter?: RateLimiterBase;
    auditSink?: AuditSinkBase;
    grantPolicy?: GrantPolicyHookBase;
    refreshTokenStore?: RefreshTokenStoreBase;
    userSessionStore?: UserSessionStoreBase;
    federationTokenStore?: FederationTokenStoreBase;
    /**
     * Lazy getter for the federation providers Map. Evaluated at request time so
     * module init order does not affect resolution — pass `() => context.federationProviders`
     * from `module.mts`. Defaults to `() => undefined` when not provided.
     */
    getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
}) => Promise<{
    router: Router;
    registry: GrantRegistry;
}>;
//# sourceMappingURL=routes.d.mts.map