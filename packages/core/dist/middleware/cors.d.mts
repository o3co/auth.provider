/**
 * middleware/cors.mts — the consumer of `cors.allowedOrigins` (#500).
 *
 * The key was declared in `application.schema.mts` and shipped in every
 * `reference.conf`, and nothing read it. A cross-origin preflight to
 * `/oauth/token` got no `Access-Control-Allow-Origin`, so a browser SPA served
 * from any origin but the provider's could not use this provider at all — and
 * an operator who set the key had no way to discover that, because a silent
 * no-op config key produces no error, no warning and no log line. That is the
 * failure the #363 declared-absence discipline exists to refuse, reached
 * through a config key rather than a DI slot.
 *
 * ### What this grants, and what it deliberately does not
 *
 * **An exact-match allowlist, and nothing else.** The `Origin` header is
 * compared to the configured entries by string equality and the matched entry
 * is echoed back. An arbitrary origin is never reflected, and `*` is never
 * emitted — not even for the unauthenticated documents, where it would be
 * harmless, because one code path that can emit `*` is one code path away from
 * emitting it on a response that carries a token.
 *
 * **An empty list means CORS is off**, which stays the default. Nothing is
 * mounted, no response gains a `Vary`, and the deployment behaves exactly as
 * it did before this middleware existed.
 *
 * **No `Access-Control-Allow-Credentials`, ever.** A cross-origin SPA here is
 * a public client using PKCE: it holds no cookie of ours and needs none. The
 * cookie it would gain access to is the one backing the `session` grant, which
 * exchanges an authenticated browser session for tokens — allowing credentials
 * would hand every allowlisted origin the ability to mint tokens for whoever
 * is signed in, which is a different and much larger grant than "may read the
 * token endpoint's response to a request it authenticated itself". The two
 * arrive together in CORS, so this list buys only the second.
 *
 * **`Vary: Origin` on every response from a CORS-enabled route**, whether an
 * `Origin` arrived or not. A shared cache that keyed only on the URL would
 * otherwise serve one origin's response — headers included — to another.
 *
 * ### Which routes
 *
 * The ones a browser legitimately calls cross-origin, and only those. See
 * {@link browserFacingCorsRoutes} for the table and the case-by-case reasons,
 * including why `/oauth/introspect` and `/oauth/authorize` are not on it.
 */
import type { RequestHandler } from "express";
import type { Logger } from "../logging/Logger.mjs";
/** One CORS-enabled endpoint: an exact path and the methods it answers. */
export interface CorsRoute {
    /** Absolute path, exactly as mounted. Matched case-insensitively. */
    readonly path: string;
    /** Methods advertised on a preflight. `OPTIONS` is implicit. */
    readonly methods: readonly string[];
}
/**
 * The endpoints CORS is enabled on, for a given config.
 *
 * **On the list**, because a browser has a legitimate reason to call each one
 * from a page served by another origin:
 *
 *   - `POST /oauth/token` — the PKCE code exchange and refresh. Without this
 *     one nothing else matters; it is the call an SPA cannot avoid.
 *   - `GET|POST /oauth/userinfo` — OIDC Core §5.3 defines both methods.
 *   - `POST /oauth/revoke` — RFC 7009 §2.1 lets a public client revoke its own
 *     tokens, which is exactly what an SPA does on sign-out.
 *   - `GET /.well-known/openid-configuration` and the JWKS document — public,
 *     unauthenticated, cacheable metadata that a browser-based client library
 *     fetches to discover the endpoints above. The JWKS path is resolved
 *     through {@link resolveJwksPath}, the same single source the route
 *     registration and the advertised `jwks_uri` use, so the three cannot
 *     drift.
 *
 * **Deliberately off the list:**
 *
 *   - `POST /oauth/introspect` is server-to-server. RFC 7662 §2.1 requires the
 *     caller to authenticate, and this provider already refuses public
 *     clients there, so a browser could never use it — enabling CORS on it
 *     would only advertise a surface no legitimate browser client has.
 *   - `GET /oauth/authorize` is a top-level navigation, not a `fetch`. CORS
 *     has no bearing on where a browser is allowed to navigate, so a header
 *     there would grant nothing and imply something false about the endpoint.
 *   - `/session/*` is cookie-backed by construction and covered by the CSRF
 *     policy at `session.csrf.trustedOrigins`, which answers the different
 *     question ("may this origin make me change state") that #272 split apart
 *     from this one.
 *
 * NOTE: the `/oauth/*` paths are coupled to the bundled `oauthModule`'s
 * mountPath, the same coupling the `/oauth/token` middleware mounts in
 * `boot/assemble-app.mts` already carry. A downstream that re-mounts the OAuth
 * router elsewhere must build its own table.
 */
export declare function browserFacingCorsRoutes(config: {
    oauth?: {
        jwt?: {
            jwksPath?: unknown;
        };
    };
}): readonly CorsRoute[];
export interface CorsMiddlewareOptions {
    /** `cors.allowedOrigins`. Entries are re-checked; invalid ones are dropped with a warning. */
    readonly allowedOrigins: readonly string[];
    /** The CORS-enabled endpoints — normally {@link browserFacingCorsRoutes}. */
    readonly routes: readonly CorsRoute[];
    readonly logger?: Logger;
}
/**
 * Build the CORS middleware, or `null` when there is nothing to do — an empty
 * (or entirely invalid) allowlist means CORS is off and no middleware should
 * be mounted at all, so that a deployment which has not opted in cannot even
 * gain a `Vary` header it did not have before.
 *
 * The re-check of `allowedOrigins` mirrors what `resolveJwksPath` does for
 * `oauth.jwt.jwksPath`: the config schema already refuses a malformed entry at
 * boot, and this repeats the check because a hand-built `AppConfig` — which
 * this codebase supports and `resolveOAuthOptions` documents — never passed
 * that schema. A dropped entry is warned about by name rather than ignored,
 * because a silently-narrowed allowlist is the same class of failure as the
 * silently-absent one this middleware exists to fix.
 */
export declare function corsMw(options: CorsMiddlewareOptions): RequestHandler | null;
//# sourceMappingURL=cors.d.mts.map