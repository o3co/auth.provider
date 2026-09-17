import type { AppConfig } from "@o3co/auth-provider-core";
import { type FederationTokenStoreBase, type UserRepository, type UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import { type FederationProvider } from "../federations/types.mjs";
declare module "express-session" {
    interface SessionData {
        /** Ephemeral federation state stored during the OAuth 2 redirect leg.
         *  Deleted by the callback handler immediately after the CSRF check (reuse prevention). */
        federation?: {
            name: string;
            state: string;
            codeVerifier: string;
            redirectTo?: string;
        };
        /** UserSession ID — set after successful federation callback. */
        sid?: string;
        isAuthenticated?: boolean;
        user?: Record<string, unknown>;
    }
}
export declare const createRouter: (express: {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
}, { config: _config, federationProviders, providerCallbackUrls, userRepository, userSessionStore, federationTokenStore, sessionTtlMs, }: {
    config: AppConfig;
    federationProviders: ReadonlyMap<string, FederationProvider>;
    providerCallbackUrls: ReadonlyMap<string, string>;
    userRepository: UserRepository;
    userSessionStore: UserSessionStoreBase;
    federationTokenStore: FederationTokenStoreBase;
    sessionTtlMs?: number;
}) => Router;
//# sourceMappingURL=Federation.d.mts.map