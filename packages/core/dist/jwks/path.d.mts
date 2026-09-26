/**
 * Default path at which the JSON Web Key Set is published. Unlike
 * `/.well-known/openid-configuration` (fixed by RFC 8414), `jwks_uri` is
 * operator-choosable per OIDC Discovery — this is the near-universal
 * convention and the default when `oauth.jwt.jwksPath` is unset.
 */
export declare const DEFAULT_JWKS_PATH = "/.well-known/jwks.json";
/**
 * Whether `path` is a valid JWKS publishing path — the SINGLE validation rule
 * shared by the config schema (`oauth.jwt.jwksPath`), {@link resolveJwksPath},
 * and `createJwksRouter`, so the registered route and the advertised `jwks_uri`
 * always agree.
 *
 * Stricter than "starts with `/`": rejects anything Express (or a URL parser)
 * could normalize to a DIFFERENT dereferenced path than the string the route
 * registers — which would silently break the route ↔ `jwks_uri` single-source
 * guarantee. Rejects `//` prefixes, `?`/`#` (query/fragment), backslashes, `%`
 * (percent-encoding, e.g. `%2e%2e`), control/whitespace characters, and `.`/`..`
 * path segments.
 */
export declare function isValidJwksPath(path: unknown): path is string;
/**
 * Resolve the JWKS publishing path for a deployment. This is the SINGLE
 * source of truth for both (a) where the JWKS route registers itself and
 * (b) the `jwks_uri` OIDC discovery advertises. The core `jwksModule` and
 * the oauth discovery route MUST both resolve the path through this
 * function so the two endpoints can never drift — neither the config key
 * (`oauth.jwt.jwksPath`) nor the default is duplicated at a call site.
 *
 * The configured value is validated by the config schema (`oauth.jwt.jwksPath`
 * via {@link isValidJwksPath}); this resolver re-applies the same check so a
 * caller that bypasses the schema (hand-built config) still falls back to the
 * default rather than publishing keys at — and advertising — a malformed path.
 */
export declare const resolveJwksPath: (config: {
    oauth?: {
        jwt?: {
            jwksPath?: unknown;
        };
    };
}) => string;
//# sourceMappingURL=path.d.mts.map