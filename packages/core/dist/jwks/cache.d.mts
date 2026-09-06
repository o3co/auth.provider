/**
 * Default `Cache-Control: public, max-age=<N>` lifetime (seconds) for the
 * JWKS response when `oauth.jwt.jwksCacheMaxAge` is unset. JWKS is the
 * most-polled verifier endpoint, so a non-zero default cuts polling load;
 * 5 minutes is short enough that a rotated key propagates quickly to
 * verifiers that cache the set. Operators with a different key-overlap
 * window tune it via config — `max-age` should stay well below the overlap
 * window so a token signed with a freshly-rotated kid is never rejected
 * longer than the cache lifetime.
 */
export declare const DEFAULT_JWKS_CACHE_MAX_AGE = 300;
/**
 * Resolve the JWKS `Cache-Control` max-age (seconds) for a deployment.
 * Consumed only by the JWKS route (discovery does not advertise cache
 * metadata), so this is not a shared anti-drift helper like
 * `resolveJwksPath` — it simply centralizes the config key + default.
 *
 * Intentionally lenient: the config schema is the authoritative guard (it
 * rejects negative / non-integer / non-number values at parse time), so at
 * runtime `configured` is either a valid non-negative integer or absent.
 * The defensive check falls back to the default for callers that bypass the
 * schema (hand-built config objects).
 */
export declare const resolveJwksCacheMaxAge: (config: {
    oauth?: {
        jwt?: {
            jwksCacheMaxAge?: unknown;
        };
    };
}) => number;
//# sourceMappingURL=cache.d.mts.map