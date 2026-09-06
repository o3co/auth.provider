/** The `aud` Apple requires on a client-secret assertion. */
export declare const APPLE_AUDIENCE = "https://appleid.apple.com";
/**
 * Apple's documented ceiling on `exp - iat` for a client secret: six months,
 * to the second. A longer-lived assertion is rejected at the token endpoint.
 */
export declare const APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS = 15777000;
/**
 * 180 days — deliberately short of the ceiling rather than exactly on it.
 * Signing at the maximum leaves nothing for clock skew between this process
 * and Apple's, and turns a boundary comparison at the token endpoint into a
 * production outage; 180 days costs one extra signature every six months.
 */
export declare const APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS: number;
/**
 * How close to `exp` a cached secret may get before it is re-signed.
 *
 * A day is long enough that no token exchange can be holding a secret that
 * expires mid-flight, and short enough that the signature is computed roughly
 * once per lifetime rather than once per request.
 */
export declare const APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS = 86400;
export interface AppleClientSecretOptions {
    /** Apple Developer Team ID — the assertion's `iss`. */
    readonly teamId: string;
    /** Services ID — the assertion's `sub`, and the OAuth `client_id`. */
    readonly clientId: string;
    /** Key ID of the downloaded `.p8`, carried in the JWT header as `kid`. */
    readonly keyId: string;
    /**
     * The `.p8` private key, PKCS#8 PEM, exactly as downloaded
     * (`-----BEGIN PRIVATE KEY-----` … ). Read at signing time rather than
     * captured at construction, so a deployment whose mounted key is repaired
     * or rotated under it recovers without a restart.
     */
    readonly privateKey: string;
    /** Defaults to {@link APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS}. */
    readonly lifetimeSeconds?: number;
    /** Clock, in milliseconds. Test seam; defaults to `Date.now`. */
    readonly now?: () => number;
}
/**
 * Build the resolver for Apple's `client_secret`: an ES256 JWT this relying
 * party signs with the `.p8` key it downloaded from the Apple Developer
 * portal.
 *
 * Apple is the only IdP in this repo whose client secret is not a string a
 * config file can hold. The assertion is:
 *
 * ```text
 * header  { alg: "ES256", kid: <Key ID> }
 * payload { iss: <Team ID>, sub: <Services ID>, aud: "https://appleid.apple.com",
 *           iat: <now>, exp: <now + lifetime ≤ 6 months> }
 * ```
 *
 * The returned function is the `FederationClientSecret` callable form the
 * session package resolves per token exchange. It caches the signed JWT and
 * re-signs only once the cached one comes within
 * {@link APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS} of `exp` — the framework
 * deliberately does not cache, because only this module knows when its secret
 * expires.
 *
 * Concurrent callers share one in-flight signature rather than each starting
 * their own, and a failed signature leaves the cache untouched so the next
 * call retries instead of inheriting a poisoned entry.
 *
 * Validation is at construction where it can be (a boot-time misconfiguration
 * should fail at boot) and at signing where it must be (the key material is
 * read late by design).
 */
export declare function createAppleClientSecret(options: AppleClientSecretOptions): () => Promise<string>;
//# sourceMappingURL=client-secret.d.mts.map