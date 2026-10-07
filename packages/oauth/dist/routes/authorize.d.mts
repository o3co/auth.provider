import { type AuditSink, type ClientRepository, type CodeRepository, type GrantPolicyHook, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";
export interface AuthorizeHandlerOptions {
    readonly clientRepository: ClientRepository;
    readonly codeRepository: CodeRepository;
    readonly grantPolicy?: GrantPolicyHook;
    readonly auditSink?: AuditSink;
    readonly logger: Logger;
    /**
     * CP-11: the canonical issuer, config-only — never request-derived (the
     * Host header is attacker-controlled in many deployments).
     */
    readonly issuer: string;
    /**
     * Login-page URL for unauthenticated sessions. A thunk, evaluated per
     * request exactly as the inline handler read `config.endpoints.login.url`,
     * so a hand-built config missing the key fails at the same point (request
     * time) it always did — `oauthModule`'s configSchema is what turns the
     * missing key into a boot failure for schema-validated deployments.
     */
    readonly loginUrl: () => string;
    /** The `oauth.*` knobs, resolved once at router composition (#328). */
    readonly oauth: ResolvedOAuthOptions;
}
/**
 * Creates the `GET /authorize` handler — the RFC 6749 §4.1.1 → §4.1.2
 * authorization-code sequence, one step per concern:
 *
 * 1. authenticate the resource owner (redirect to login) — the #325
 *    rate-limit guard runs before this handler, mounted as sibling
 *    middleware on the route;
 * 2. identify the client and validate `redirect_uri` (§4.1.1; 400 JSON —
 *    no trusted redirect target yet, per A-1);
 * 3. validate the request: `response_type`, the client's registered grant
 *    types (#268), the first-party invariant (#267), the email-verified
 *    gate (#297), PKCE — mandatory, S256 (#273) — `nonce` bounds (IH-16);
 * 4. narrow scope and audience: client allowlist + openid requirement
 *    (IH-6), then policy (C-2), then the RFC 8707 resource check;
 * 5. issue the code and redirect back with `code` + `state` (§4.1.2).
 *
 * Extracted from the inline `routes.mts` closure in #328 with behavior
 * intentionally identical: same checks, same order, same error responses,
 * same audit payloads.
 */
export declare const createAuthorizeHandler: (opts: AuthorizeHandlerOptions) => RequestHandler;
//# sourceMappingURL=authorize.d.mts.map