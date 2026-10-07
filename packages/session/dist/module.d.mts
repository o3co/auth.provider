import { type Module, type UserRepository } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import { type FederationProviderFactory } from "./federations/factory.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export type SessionModuleOptions = {
    userRepository: UserRepository;
    express?: ExpressLike;
    /** Session TTL in milliseconds for new federation-created UserSessions. Default 24h. */
    sessionTtlMs?: number;
};
type SessionModuleInternalOptions = SessionModuleOptions & {
    /** For testing only — inject a pre-configured factory to skip registration. */
    _federationFactory?: FederationProviderFactory;
    /** For testing only — replace sessionRoutes.createRouter to capture call arguments. */
    _createSessionRouter?: typeof sessionRoutes.createRouter;
    /** For testing only — replace federationRoutes.createRouter to capture call arguments. */
    _createFederationRouter?: typeof federationRoutes.createRouter;
};
/**
 * Internal implementation — accepts an optional factory override for testing.
 * Not part of the public API; tests import this directly via the `#/` alias.
 */
export declare const _sessionModuleImpl: (params: SessionModuleInternalOptions) => Module;
/**
 * Top-level session module factory.
 *
 * Public API — does not expose test-only options. Tests should use `_sessionModuleImpl` directly.
 */
export declare const sessionModule: (opts: SessionModuleOptions) => Module;
export {};
//# sourceMappingURL=module.d.mts.map