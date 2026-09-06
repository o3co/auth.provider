/**
 * JWKS publishing module. Contributes the `/.well-known/jwks.json` route
 * (or the `oauth.jwt.jwksPath` override) so every provider that signs
 * tokens exposes its verification keys for offline validation by verifiers
 * (BFFs, RPs).
 *
 * Unlike OIDC discovery (issuer-gated, contributed by the oauth module),
 * JWKS publishing is a key-management concern: it depends ONLY on the
 * `keyStore` and is mounted whenever the provider signs tokens, independent
 * of whether an OIDC issuer is configured. For HS256 (symmetric) the route
 * returns an empty key set — the secret is never published.
 *
 * The route registers an absolute path, so the contribution mounts at "/"
 * to avoid path doubling.
 *
 * `express` is resolved lazily inside the (async) route factory via
 * `createRequire` rather than a static import. core declares `express` as
 * an OPTIONAL peer dependency; a static import would make
 * `@o3co/auth-provider-core` fail to load for non-HTTP consumers that omit
 * this module from their manifest. Mirrors the peer-resolution pattern in
 * `boot/assemble-app.mts`.
 */
export declare const jwksModule: import("../modules/index.mjs").Module;
//# sourceMappingURL=module.d.mts.map