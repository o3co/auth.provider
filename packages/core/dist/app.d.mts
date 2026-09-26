import type { RequestHandler, Router } from "express";
import type { AuditSinkBase } from "./audit/types.mjs";
import type { CoreConfig } from "./config/application.schema.mjs";
import type { FederationTokenStoreBase } from "./federation-tokens/types.mjs";
import { GrantRegistry } from "./grants/registry.mjs";
import type { KeyStore } from "./keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "./mfa/types.mjs";
import type { Module, PathResolver } from "./modules/types.mjs";
import type { GrantPolicyHookBase } from "./policy/types.mjs";
import type { RateLimiterBase } from "./ratelimit/types.mjs";
import type { RefreshTokenStoreBase } from "./refresh/types.mjs";
import type { UserSessionStoreBase } from "./user-sessions/types.mjs";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface AppOptions {
    express?: ExpressLike;
    pathResolver?: PathResolver;
    config: CoreConfig & Record<string, unknown>;
    keyStore: KeyStore;
    modules: Module[];
    mfaProviderFactory?: MfaProviderFactory;
    mfaCoordinator?: MfaCoordinator;
    mfaTransactionStore?: MfaTransactionStore;
    auditSink?: AuditSinkBase;
    rateLimiter?: RateLimiterBase;
    refreshTokenStore?: RefreshTokenStoreBase;
    grantPolicy?: GrantPolicyHookBase;
    userSessionStore?: UserSessionStoreBase;
    federationTokenStore?: FederationTokenStoreBase;
}
export interface AppResult {
    init(): Promise<void>;
    router: Router;
    grantRegistry: GrantRegistry;
}
export declare function createApp(options: AppOptions): AppResult;
export {};
//# sourceMappingURL=app.d.mts.map