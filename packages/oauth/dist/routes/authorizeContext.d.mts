/**
 * What every `/authorize` stage reads: the handler's options, the request's
 * parameters and its GET URL on the issuer's origin, and the per-request
 * context, which exists only once `redirect_uri` is validated.
 */
import { type AuditSink, type ClientRepository, type CodeRepository, type ConsentStore, type GrantPolicyHook, type Logger, type LoginEntry, type PendingConsentStore, type SessionLifecycleStore, type SessionRequirementResolver, type SubjectRevocation, type UserSessionStore } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";
import type { AuthorizationResponse } from "./authorizationResponse.mjs";
export interface AuthorizeHandlerOptions {
    readonly clientRepository: ClientRepository;
    readonly codeRepository: CodeRepository;
    readonly grantPolicy?: GrantPolicyHook;
    readonly auditSink?: AuditSink;
    readonly logger: Logger;
    /** The canonical issuer, config-only: never request-derived (Host is attacker-controlled). */
    readonly issuer: string;
    /** Builds a response to `redirect_uri`, its `iss` (RFC 9207) bound. */
    readonly authorizationResponse: AuthorizationResponse;
    /**
     * The login trip for a browser that must log in: `urlFor(returnTo)` is the
     * login page with the request to come back to — the `loginEntry` slot's.
     */
    readonly login: Pick<LoginEntry, "urlFor">;
    /**
     * Consent-page URL for a client that is not first-party. A thunk, evaluated
     * per request.
     */
    readonly consentUrl: () => string;
    /** Where consent records live. Without it a client that is not first-party is refused. */
    readonly consentStore?: ConsentStore;
    /**
     * Where a request is parked while the consent page asks. Wired with
     * `consentStore`; the router refuses one without the other.
     */
    readonly pendingConsentStore?: PendingConsentStore;
    /** The `oauth.*` knobs, resolved once at router composition. */
    readonly oauth: ResolvedOAuthOptions;
    /**
     * The durable session store admission reads the cookie's session from.
     * Without it (no session-backed login) admission decides on the cookie alone.
     */
    readonly userSessionStore?: UserSessionStore;
    /** The session lifecycle's record admission reads after a live session: closing is not live. */
    readonly sessionLifecycleStore?: SessionLifecycleStore;
    /**
     * The subject-revocation boundary admission applies to the live record: a
     * session established before the subject's sessions were revoked is refused
     * here too, not only at the token side.
     */
    readonly subjectRevocation?: SubjectRevocation;
    /**
     * The registered session requirements admission asks about. Required: a
     * handler built without one is refused.
     */
    readonly requirements: SessionRequirementResolver;
}
/**
 * Per-request state threaded through the §4.1 stages. Constructed only
 * after `resolveClientAndRedirectUri` validated `redirect_uri` against the
 * client allowlist, so holding it is itself the proof that redirect-based
 * errors (RFC 6749 §4.1.2.1) are permitted.
 */
export interface AuthorizeContext {
    readonly req: Request;
    readonly res: Response;
    readonly opts: AuthorizeHandlerOptions;
    /** The configured issuer's origin — what a parked request's URL is built from. */
    readonly issuerOrigin: string;
    readonly clientId: string;
    readonly redirectUri: string;
    /** Verbatim `state` when it was a single string; echoed on every response. */
    readonly state: string | undefined;
    /**
     * The request's parameters — query string on GET, form body on POST — so
     * every check reads the same object however the request arrived.
     */
    readonly params: Record<string, unknown>;
}
export declare const toStr: (v: unknown) => string | undefined;
/**
 * The authorization request's parameters: a POST's form body or a GET's
 * query (OIDC Core §3.1.2.1 requires both methods). Read in one place so no
 * check silently applies to GET alone.
 */
export declare const authorizeParams: (req: Request) => Record<string, unknown>;
/**
 * This authorization request as a GET URL on the issuer's origin, with a
 * POST's form parameters written as the query: what the consent, login and
 * step-up pages return to, and what an ask is bound to. Not
 * `req.originalUrl`: a POST's URL alone names no client, `redirect_uri` or
 * PKCE.
 */
export declare const authorizeRequestUrl: (issuerOrigin: string, req: Request) => URL;
/**
 * `url` less `prompt=consent`, which the consent round trip answers — carried
 * back, it would park the request again forever. Other prompt values stay,
 * read as `resolvePrompt` reads them; a malformed `prompt` was refused there
 * and is left as it is. The request the consent step resumes, and the one a
 * re-authentication ask is bound to, so the two agree.
 */
export declare const withoutConsentPrompt: (url: URL) => URL;
//# sourceMappingURL=authorizeContext.d.mts.map