import { type AuditSink, type ClientRepository, type FederationGrantAcquisitionConnection, type FederationGrantIntentStore, type FederationGrantStore, type Logger, type RateLimiter, type RateLimitFailMode, type UserRepository, type UserSessionStore } from "@o3co/auth-provider-core";
import type { SupportsDelegatedAuthorization } from "@o3co/auth-provider-session";
import { type Router } from "express";
import type { FederationGrantBackground } from "./background.mjs";
/** Where this router is mounted. */
export declare const FEDERATION_GRANTS_BROWSER_MOUNT_PATH = "/session/federation-grants";
/**
 * What the connect flow needs of a federation (D17): the authorization URL the
 * consent answer sends the user to, and the exchange the callback makes. The
 * capability's refresh is the token route's business, not this router's.
 */
export type FederationGrantDelegatedAuthorizer = Pick<SupportsDelegatedAuthorization, "buildDelegatedAuthorizationUrl" | "exchangeDelegatedCode">;
export interface FederationGrantBrowserRouterOptions {
    readonly intentStore: FederationGrantIntentStore;
    readonly grantStore: FederationGrantStore;
    readonly clientRepository: ClientRepository;
    /** The durable sessions behind the cookie, re-read at every step. */
    readonly userSessionStore: UserSessionStore;
    /** The subject's SESSIONS boundary (D13): a session must have authenticated after it. */
    readonly sessionsBoundary: (subject: string) => Promise<Date | null>;
    readonly revocationSkewMs: number;
    readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
    /** The federation's delegated authorizer, or `undefined` when it has none. */
    readonly authorizerFor: (federation: string) => FederationGrantDelegatedAuthorizer | undefined;
    /** `federationGrants.consent.url`: a path, or an absolute URL on the provider's origin. */
    readonly consentUrl: string;
    /** `endpoints.login.url`, read per request as `/authorize` reads it. */
    readonly loginUrl: () => string;
    /** `oauth.jwt.issuer`: every URL this router builds is built on it. */
    readonly issuer: string;
    readonly rateLimiter: RateLimiter;
    readonly failMode: RateLimitFailMode;
    readonly background: FederationGrantBackground;
    /** The subject's GRANTS boundary (D13): what the callback's backstop and re-read compare a consent with. */
    readonly grantsBoundary: (subject: string) => Promise<Date | null>;
    /** D7 check 5: whether an upstream account linked to another local user is refused. */
    readonly identityLookup: "required" | "unsupported";
    /** The port's own signature, not a copy of it: the two cannot drift apart (#611). */
    readonly userRepository?: Pick<UserRepository, "findSubjectByFederatedIdentity">;
    /** Milliseconds: where the code exchange is aborted (`upstreamHardTimeoutMs`). */
    readonly upstreamTimeoutMs: number;
    readonly now?: () => Date;
    /** 256 random bits, base64url. A seam for tests. */
    readonly randomId?: () => string;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
/** The limiter tag; a budget of its own, apart from the JSON routes'. */
export declare const FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX = "federation_grants_browser";
export declare function createFederationGrantBrowserRouter(options: FederationGrantBrowserRouterOptions): Router;
/** What a disabled deployment mounts here: a plain 404, indistinguishable from nothing. */
export declare function createDisabledFederationGrantBrowserRouter(): Router;
//# sourceMappingURL=browserRoutes.d.mts.map