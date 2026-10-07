/** The component map as boot holds it. */
type Components = Readonly<Record<string, unknown>>;
/**
 * The issuer: the slot's when the composition holds it — the snapshot
 * stage 3 put there (`token-settings-slot.mts`), already held to the
 * contract and the configured lifetimes, read whole through
 * `checkOAuthTokenSettings`, so a slot without a canonical issuer refuses
 * rather than the configuration's being read beside it — else
 * `oauth.jwt.issuer` as the configuration carries it, canonical where boot
 * parsed it (held to `isCanonicalIssuer` here too, for a component map built
 * by hand), and `undefined` with none: then no discovery document is served,
 * the CORS table guards no discovery path (`browserFacingCorsRoutes`, handed
 * this issuer alone), and a requirement's page is held to no issuer's
 * origin.
 */
export declare function compositionIssuer(components: Components): string | undefined;
export {};
//# sourceMappingURL=oauth-token-settings.d.mts.map