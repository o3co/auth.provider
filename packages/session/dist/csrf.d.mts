import { type Logger } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
/** Default cookie carrying the double-submit value. */
export declare const DEFAULT_CSRF_COOKIE_NAME = "auth.csrf";
/** Default header the client echoes the cookie value back in. */
export declare const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
/** Default body field for form posts that cannot set a header. */
export declare const DEFAULT_CSRF_BODY_FIELD = "csrf_token";
/** Default token lifetime. Two hours: long enough to outlive a login form. */
export declare const DEFAULT_CSRF_TTL_SECONDS = 7200;
/**
 * Ceiling on the token lifetime, in seconds (24 hours).
 *
 * A policy bound rather than a mechanical one. The token exists to outlive a
 * login form sitting open; past a day it stops being that and becomes a
 * long-lived bearer value sitting in a JS-readable cookie. `reference.conf`
 * and the `session.csrf.ttlSeconds` schema restate this number — the schema
 * cannot import it, since `session` depends on `core` and not the reverse, so
 * a test in this package pins the two together.
 */
export declare const MAX_CSRF_TTL_SECONDS = 86400;
/**
 * What the token arm concluded.
 *
 * `absent` and `invalid` are kept apart deliberately: absence is the ordinary
 * state of a browser request that is relying on the origin arm, while
 * `invalid` means material was presented and did not check out.
 */
export type CsrfTokenVerdict = "valid" | "absent" | "invalid";
/** What the origin arm concluded. */
export type CsrfOriginVerdict = "same-origin" | "trusted" | "foreign" | "absent";
/** Transport attributes for the CSRF cookie — mirror the session cookie's. */
export interface CsrfCookieAttributes {
    readonly secure: boolean;
    readonly sameSite: "lax" | "strict" | "none";
    readonly domain?: string | undefined;
}
export interface CsrfProtectionOptions {
    /**
     * Secret the signing key is derived from. Pass `session.secret`; the key
     * itself is an HKDF expansion of it, never the secret.
     */
    readonly secret: string;
    readonly cookieName?: string;
    readonly headerName?: string;
    readonly bodyField?: string;
    readonly ttlSeconds?: number;
    readonly cookie?: CsrfCookieAttributes;
    /** Clock seam for tests. */
    readonly now?: () => number;
}
export interface CsrfProtection {
    readonly cookieName: string;
    readonly headerName: string;
    readonly bodyField: string;
    readonly ttlSeconds: number;
    /** Mint a signed token without touching the response. */
    mint(): string;
    /** Mint a token and set the paired cookie on `res`. Returns the token. */
    issue(res: Response): string;
    /** Check the double-submit pair carried by `req`. */
    verify(req: Request): CsrfTokenVerdict;
}
export declare const createCsrfProtection: (options: CsrfProtectionOptions) => CsrfProtection;
/**
 * Classify a request's `Origin` — falling back to `Referer` — against the
 * server's own origin and an explicit trust list.
 *
 * Behind a reverse proxy the server origin is only correct when the app sets
 * `trust proxy`; `req.protocol` and `req.host` then read the forwarded values,
 * which is what the browser actually put in `Origin`.
 *
 * A header that is present but does not parse — `Origin: null` from a
 * sandboxed frame, a relative `Referer` — is `foreign`, not `absent`. Absent
 * means the request carried no origin signal at all; a signal that fails to
 * name this origin is not the same thing.
 */
export declare const checkRequestOrigin: (req: Request, trustedOrigins?: readonly string[]) => CsrfOriginVerdict;
export interface CsrfGuardOptions {
    readonly csrf: CsrfProtection;
    /**
     * Origins other than the server's own that may satisfy the origin arm.
     *
     * Deliberately **not** `cors.allowedOrigins`: "this origin may read my
     * responses" and "this origin may make me change state" are two decisions,
     * and #272 was filed because one list was answering both.
     */
    readonly trustedOrigins?: readonly string[];
    readonly logger?: Logger;
}
/**
 * The acceptance rule.
 *
 * - A **foreign** `Origin` / `Referer` is rejected outright, token or no token.
 *   A foreign origin is positive evidence that a browser made this request from
 *   another site; the pre-#272 guard already rejected it and a security fix must
 *   not hand that back. A legitimate non-browser client simply sends no
 *   `Origin`, so nothing that worked before is lost.
 * - A **same-origin or trusted** signal is accepted on its own. This is what
 *   keeps the ordinary browser login form working with no client change.
 * - When **no** origin signal is present — the header-less API client, and the
 *   exact case the old code waved through — a valid double-submit token is
 *   required.
 *
 * So the two arms are alternatives for *presence*, and the origin arm is
 * authoritative when it is present. Rejection happens when both are missing, or
 * when either positively contradicts the request.
 */
export declare const createCsrfGuard: ({ csrf, trustedOrigins, logger, }: CsrfGuardOptions) => RequestHandler;
/**
 * Handler for the endpoint that hands a browser its first token.
 *
 * The endpoint is unauthenticated and stateless, so an attacker can fetch a
 * token of their own — which buys them nothing. Forging a request still
 * requires writing the victim's cookie for this origin, which is what the
 * same-site cookie boundary denies them.
 */
export declare const createCsrfIssueHandler: (csrf: CsrfProtection) => RequestHandler;
/**
 * The `session.*` slice this module reads. Declared structurally so the helper
 * can be called with a partial config in tests without an `AppConfig` cast.
 */
export interface SessionCsrfConfigSlice {
    readonly secret: string;
    readonly name: string;
    readonly secure: boolean;
    readonly sameSite: "lax" | "strict" | "none";
    readonly domain: string | null;
    readonly csrf?: {
        readonly trustedOrigins?: readonly string[];
        readonly ttlSeconds?: number;
    } | undefined;
}
/**
 * Build the protection from the `session` config slice.
 *
 * The cookie name is derived as `<session.name>.csrf` rather than configured
 * separately, so it inherits whatever prefix the session cookie already
 * carries. That matters for `__Host-`: the boot guard in `sessionStoreModule`
 * already refuses a `__Host-` session name unless `secure` is on and no domain
 * is set, and deriving from it means the CSRF cookie can never disagree with
 * that verdict — a `__Host-` cookie the browser silently drops would look
 * exactly like a client that forgot to send the token.
 */
export declare const createCsrfProtectionFromConfig: (session: SessionCsrfConfigSlice, overrides?: Partial<CsrfProtectionOptions>) => CsrfProtection;
//# sourceMappingURL=csrf.d.mts.map