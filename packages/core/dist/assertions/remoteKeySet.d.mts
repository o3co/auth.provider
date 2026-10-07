/**
 * A remote JSON Web Key Set — the one place this library turns a `jwks_uri`
 * into a verification key resolver.
 *
 * jose's `createRemoteJWKSet` caches the document, refetches on an unknown
 * `kid` (with a cooldown, so a flood of bad kids is not a flood of fetches)
 * and refreshes it after `cacheMaxAge`. That cache lives in the resolver, so a
 * resolver made per request is a fetch per request; the memo here is what
 * makes a rotation cost one refetch.
 *
 * Two consumers had their own copy — `private_key_jwt` client assertions
 * (#484) and the trust-registry assertion verifier (#525) — with the same
 * memo and the same tuning, and only the first took a fetch. A deployment
 * behind an egress proxy could fetch a client's keys and not a trusted
 * issuer's (v0.13.0 audit). Both build on this now.
 */
import { createRemoteJWKSet } from "jose";
/** Fetch timeout for a key set. */
export declare const DEFAULT_REMOTE_JWKS_TIMEOUT_MS = 5000;
/** Minimum interval between refetches an unknown `kid` triggers. */
export declare const DEFAULT_REMOTE_JWKS_COOLDOWN_MS = 30000;
/** How long a fetched key set is served without refetching. */
export declare const DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS = 600000;
/** A key resolver for `jwtVerify`, backed by one remote key set. */
export type RemoteKeySet = ReturnType<typeof createRemoteJWKSet>;
/** Per-key-set tuning. Each absent field is its `DEFAULT_REMOTE_JWKS_*`. */
export interface RemoteKeySetTuning {
    readonly timeoutMs?: number | undefined;
    readonly cooldownMs?: number | undefined;
    readonly cacheMaxAgeMs?: number | undefined;
}
export interface RemoteKeySetCacheOptions {
    /** The fetch every key set uses. An egress proxy, or a test seam. */
    readonly fetch?: typeof fetch | undefined;
}
export interface RemoteKeySetCache {
    /**
     * The key set at `uri` under `tuning` — the same one for the same pair, so
     * a caller whose `uri` arrives on a fresh object per request (a registry
     * over a store) still shares one cache. Different tuning is a different key
     * set: the first caller's options do not become every later caller's.
     */
    keySetFor(uri: string, tuning?: RemoteKeySetTuning): RemoteKeySet;
}
export declare function createRemoteKeySetCache(options?: RemoteKeySetCacheOptions): RemoteKeySetCache;
//# sourceMappingURL=remoteKeySet.d.mts.map