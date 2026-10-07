import { type AdmissionDeps, type AuditSink, type ClientRepository, type CsrfGuard, type FederationGrantAcquisitionConnection, type FederationGrantAuditEvent, type FederationGrantIntent, type FederationGrantIntentStore, type FederationGrantStore, type Logger, type LoginEntry, type RateLimiter, type SessionLifecycleStore, type SessionRequirementResolver, type SubjectRevocation, type SupportsDelegatedAuthorization, type UserRepository, type UserSessionStore } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { FederationGrantBackground } from "./background.mjs";
import { type FederationGrantLog, type LogFields } from "./log.mjs";
/**
 * What the connect flow needs of a federation: the authorization URL the consent
 * answer sends the user to, and the callback's code exchange. Refresh is the token
 * route's business.
 */
export type FederationGrantDelegatedAuthorizer = Pick<SupportsDelegatedAuthorization, "buildDelegatedAuthorizationUrl" | "exchangeDelegatedCode">;
export interface FederationGrantBrowserRouterOptions {
    readonly intentStore: FederationGrantIntentStore;
    readonly grantStore: FederationGrantStore;
    /**
     * The `clientRepository` slot, which holds core's client-record boundary:
     * each record it answers is validated and frozen, and a refused one rejects.
     */
    readonly clientRepository: ClientRepository;
    /** The durable sessions behind the cookie, which admission re-reads at every step. */
    readonly userSessionStore: UserSessionStore;
    /**
     * Where admission reads the subject's SESSIONS boundary, which a session must have
     * authenticated after. The grants boundary is `grantsBoundary`.
     */
    readonly subjectRevocation: SubjectRevocation;
    /**
     * The session lifecycle port admission reads after a live record, so a
     * session closing or closed connects nothing. Required beside
     * `userSessionStore`: core's session lifecycle is required where a
     * user-session store is wired.
     */
    readonly sessionLifecycleStore?: SessionLifecycleStore | undefined;
    /**
     * The `sessionRequirementResolver` the boot planner built (`resolverForTests` in
     * tests): the session requirements admission asks. Admission refuses any other
     * object.
     */
    readonly requirements: SessionRequirementResolver;
    /** The clock-skew allowance the GRANTS boundary is compared with. */
    readonly revocationSkewMs: number;
    readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
    /** The federation's delegated authorizer, or `undefined` when it has none. */
    readonly authorizerFor: (federation: string) => FederationGrantDelegatedAuthorizer | undefined;
    /** `federation-grants.consent.url`: a path, or an absolute URL on the provider's origin. */
    readonly consentUrl: string;
    /**
     * The login page a browser that is not signed in is sent to, and its
     * `redirect_to` protocol: the session module's `loginEntry` slot.
     */
    readonly login: Pick<LoginEntry, "urlFor">;
    /**
     * The deployment's CSRF policy, the `csrfGuard` slot the session module
     * provides: the consent answer is held to its request rule.
     */
    readonly csrfGuard: Pick<CsrfGuard, "check">;
    /** `oauth.jwt.issuer`, held to core's `checkCanonicalIssuer`: every URL this router builds is built on it. */
    readonly issuer: string;
    /**
     * The browser budget; its own `failMode` is the outage policy. Absent, the
     * pages are not throttled.
     */
    readonly rateLimiter?: RateLimiter;
    readonly background: FederationGrantBackground;
    /**
     * The subject's GRANTS boundary: what the callback's backstop and re-read
     * compare a consent with.
     */
    readonly grantsBoundary: (subject: string) => Promise<Date | null>;
    /** Callback check 5: whether the Store is asked who holds the upstream account. */
    readonly identityLookup: "required" | "unsupported";
    /** The port's own signature, not a copy of it, so the two cannot drift apart. */
    readonly userRepository?: Pick<UserRepository, "findSubjectByFederatedIdentity">;
    /** Milliseconds: where the code exchange is aborted (`upstreamHardTimeoutMs`). */
    readonly upstreamTimeoutMs: number;
    readonly now?: () => Date;
    /** 256 random bits, base64url. A seam for tests. */
    readonly randomId?: () => string;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
/**
 * What could not answer, for the one line an outage writes: the store (or
 * `client`, the client registry, which core's own line reports), what it was
 * asked, and what it threw. The session's part is admission's, which writes
 * its own line.
 */
export interface Unanswered {
    readonly store: "federation_grant" | "federation_grant_intent" | "revocation_boundary" | "user_directory" | "client";
    readonly step: string;
    readonly error: unknown;
}
/** What every stage is handed. */
export interface BrowserFlow {
    readonly options: FederationGrantBrowserRouterOptions;
    readonly now: () => Date;
    readonly randomId: () => string;
    readonly log: FederationGrantLog;
    readonly admissionFor: (flow: LogFields) => AdmissionDeps;
    readonly auditFor: (req: Request) => (event: FederationGrantAuditEvent) => Promise<void>;
    readonly failed: (req: Request, res: Response, outcome: string, intent?: FederationGrantIntent) => void;
}
/**
 * Throws where a user-session store is wired without the session lifecycle
 * port: admission would skip the lifecycle record, and a closing session
 * could connect.
 */
export declare function requireSessionLifecycleStore(deps: {
    readonly userSessionStore?: UserSessionStore | undefined;
    readonly sessionLifecycleStore?: SessionLifecycleStore | undefined;
}): void;
/**
 * The flow's shared part, derived once. `requirements` and `subjectRevocation` are
 * the ones the router has already checked.
 */
export declare function createBrowserFlow(options: FederationGrantBrowserRouterOptions, requirements: SessionRequirementResolver, subjectRevocation: SubjectRevocation): BrowserFlow;
//# sourceMappingURL=browserFlow.d.mts.map