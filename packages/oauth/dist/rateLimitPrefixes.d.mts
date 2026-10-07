/**
 * The prefixes the OAuth endpoints limit under (`<prefix>:ip:<ip>`): the ones
 * the router keys and the oauth module claims.
 */
export declare const OAUTH_RATE_LIMIT_PREFIXES: Readonly<{
    readonly token: "token";
    readonly authorize: "authorize";
    readonly introspect: "introspect";
    readonly revoke: "revoke";
}>;
//# sourceMappingURL=rateLimitPrefixes.d.mts.map