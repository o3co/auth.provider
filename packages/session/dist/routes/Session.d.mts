import { type AppConfig, type UserRepository, type UserSessionStoreBase } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
declare module "express-session" {
    interface SessionData {
        isAuthenticated?: boolean;
        user?: Record<string, unknown>;
        redirectTo?: string;
        /** UserSession ID — set by local login and preserved across session regeneration. */
        sid?: string;
    }
}
export declare const createRouter: (express: {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
}, { userRepository, config, userSessionStore, sessionTtlMs, }: {
    userRepository: UserRepository;
    config: AppConfig;
    userSessionStore?: UserSessionStoreBase;
    /** Session TTL in milliseconds. Default: 24h. */
    sessionTtlMs?: number;
}) => Router;
//# sourceMappingURL=Session.d.mts.map