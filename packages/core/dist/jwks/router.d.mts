import type { Router } from "express";
import type { KeyStore } from "../keys/KeyStore.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
/** Options for {@link createRouter}. */
export interface JwksRouterOptions {
    /**
     * Absolute path the router registers internally. Defaults to
     * {@link DEFAULT_JWKS_PATH}. Callers honoring the `oauth.jwt.jwksPath`
     * override resolve it via `resolveJwksPath` and pass the result here so
     * the registered path matches the advertised `jwks_uri`.
     */
    path?: string;
    /**
     * `Cache-Control: public, max-age=<N>` lifetime in seconds for the JWKS
     * response. Defaults to {@link DEFAULT_JWKS_CACHE_MAX_AGE}. Callers
     * honoring `oauth.jwt.jwksCacheMaxAge` resolve it via
     * `resolveJwksCacheMaxAge`. Keep well below the key-overlap window so a
     * freshly-rotated kid propagates to caching verifiers in time.
     */
    cacheMaxAgeSeconds?: number;
    /**
     * Where the `503 jwks_unavailable` answer is logged, at error level, as
     * `jwks_unavailable` with the algorithm and the number of keys the
     * keystore returned. Absent, it is not logged.
     */
    logger?: EventLogger;
}
/**
 * Build the JWKS publishing Router. The router registers `path` as an
 * **absolute** path internally, so the effective endpoint is the router's
 * mount point + `path`. Mount at the application root (`app.use(createRouter(
 * express, keyStore))`) for the common case. Prefix-mounting (e.g.
 * `app.use("/auth", createRouter(...))`) is valid only when the advertised
 * `jwks_uri` carries the same base path — typically because the issuer
 * identifier itself has that prefix (`jwks_uri = ${issuer}${path}`). If the
 * mount prefix and the issuer prefix disagree, discovery advertises a
 * `jwks_uri` that does not resolve. (The core `jwksModule` mounts at "/" and
 * relies on the issuer prefix to carry any base path.)
 *
 * A successful response carries `Cache-Control: public, max-age=N`, where N is
 * `cacheMaxAgeSeconds` (JWKS is public data and the most-polled verifier
 * endpoint).
 *
 * The route never publishes an empty key set (#282). A symmetric (HS256)
 * keystore answers `404 jwks_not_published`; an asymmetric keystore that
 * yields no exportable public key answers `503 jwks_unavailable`. Both carry
 * `Cache-Control: no-store` so the condition is not pinned in a shared cache
 * after the operator fixes it.
 *
 * Direct callers bypass the config schema, so `path` and `cacheMaxAgeSeconds`
 * are validated here and the factory throws on misconfiguration (a non-
 * absolute path or a negative / non-integer cache age) — failing fast at
 * boot rather than registering an unexpected route or emitting an invalid
 * `Cache-Control` header.
 */
export declare const createRouter: (express: {
    Router: () => Router;
}, keyStore: KeyStore, opts?: JwksRouterOptions) => Router;
//# sourceMappingURL=router.d.mts.map