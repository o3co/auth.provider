/**
 * What the federation stages share: the router's context, built once when the
 * router is. A stage reads the context and never changes it.
 */
import type { Admission, AuditSink, FederationProvider, FederationTokenStore, Logger, SessionClaim, SessionLifecycle, UserRepository } from "@o3co/auth-provider-core";
import type { SessionAdmissionAction } from "../admissionActions.mjs";
import type { FederationRedirectPolicy } from "../federations/redirect-policy.mjs";
import type { FederationTransactionCookie } from "./FederationTransactionCookie.mjs";
/** The router's options the stages read, and what the router derives from them once. */
export interface FederationRouterContext extends FederationTransactionCookie {
    readonly federationProviders: ReadonlyMap<string, FederationProvider>;
    readonly federationRedirectPolicyResolver: ReadonlyMap<string, FederationRedirectPolicy>;
    readonly providerCallbackUrls: ReadonlyMap<string, string>;
    readonly userRepository: UserRepository;
    readonly federationTokenStore: FederationTokenStore;
    /**
     * Core's session lifecycle: a link reads the federations a session joined
     * from it, and a federation joins a session through it once its tokens
     * are attached.
     */
    readonly sessionLifecycle: SessionLifecycle;
    readonly federationTransactionTtlMs: number;
    readonly auditSink: AuditSink | undefined;
    readonly logger: Logger;
    /** The origins besides this one a link may be started from (`session.csrf.trustedOrigins`). */
    readonly linkTrustedOrigins: readonly string[];
    /** The link flow's one reading of a session: admission, with the router's slots. */
    readonly admitLink: (claim: SessionClaim, action: SessionAdmissionAction, log: Logger) => Promise<Admission>;
}
//# sourceMappingURL=FederationContext.d.mts.map