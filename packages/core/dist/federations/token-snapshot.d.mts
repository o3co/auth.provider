/**
 * An RFC 6749 §5.1 token response as the adapter's OAuth library hands it
 * over after validating it: `access_token` and `token_type` are strings,
 * `expires_in` a number and `scope` a string when present. openid-client's
 * answer is this shape — oauth4webapi refuses a non-string scope, lower-cases
 * `token_type`, and applies `parseFloat` to an `expires_in` that is not a
 * number (`"1000seconds"` reads as 1000, `[3600, 7200]` as 3600) before the
 * adapter sees it. Declared here so that no vendor type reaches this contract.
 */
export interface FederationTokenResponse {
    readonly access_token: string;
    readonly token_type: string;
    readonly expires_in?: number;
    readonly refresh_token?: string;
    readonly id_token?: string;
    readonly scope?: string;
}
/**
 * The token fields of a `FederationProfile` or a `RefreshedTokens`, as one
 * response states them. A type alias rather than an interface so that it is
 * assignable to `RefreshedTokens`, whose extension slot is an index signature.
 */
export type FederationTokenSnapshot = {
    readonly accessToken: string;
    readonly refreshToken?: string;
    readonly idToken?: string;
    /** `obtainedAt + expiresIn`, or `null` when the response stated no lifetime. */
    readonly expiresAt: Date | null;
    /** `expires_in` as the library read it, or `null` when the response carried none. */
    readonly expiresIn: number | null;
    /** Present exactly when the response carried a `scope` — an empty one included, `""` for a non-string. */
    readonly scope?: string;
    readonly tokenType: string;
};
/**
 * Read a token response the way every adapter does.
 *
 * - **Lifetime.** `expires_in` as the adapter's library read it — the
 *   snapshot sees only the library's answer, so `"1000seconds"` has already
 *   become 1000 — and `expiresAt` dated from `obtainedAt`: when the library
 *   handed the answer over, after it verified any id_token (a JWKS fetch
 *   included), and before the adapter calls UserInfo or anything else. The
 *   delegated reader in `federation-oidc` reads the raw body and the arrival
 *   time instead, and refuses a lifetime that is not a number: a grant's
 *   eligibility judges the lifetime a token was issued with against an
 *   operator's maximum (#593, D5), where a login's expiry only says when a
 *   refresh is due. An absent `expires_in` is `null` on both fields: the
 *   upstream stated no lifetime, and one is not invented for it.
 *   `FederationProfile.expiresAt` asks each adapter for that decision so the
 *   route layer never invents a fallback expiry; an adapter that assumed an
 *   hour was inventing one in its place. It is also what
 *   `POST /oauth/federation/:name/token` already stores for a refresh that
 *   states nothing.
 * - **Scope.** Present exactly when the response carried one, an empty one
 *   included, and `""` for one that is not a string: the session route reads
 *   an absent scope as "as requested" (RFC 6749 §3.3), so an answer that
 *   named nothing usable must not flatten into silence (#647). The bundled
 *   adapters' library refuses a non-string scope first; this holds for any
 *   other caller.
 * - **Refresh token and id_token** only when they are non-empty strings; an
 *   empty one is not a credential.
 * - **Token type** as the library reported it, which is what
 *   `POST /oauth/federation/:name/token` judges before it hands a token on
 *   (#645).
 */
export declare function federationTokenSnapshot(response: FederationTokenResponse, obtainedAt?: number): FederationTokenSnapshot;
//# sourceMappingURL=token-snapshot.d.mts.map