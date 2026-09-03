/**
 * Compute the `ath` claim value for an access token — RFC 9449 §4.2.
 *
 * `base64url(SHA-256(ASCII(access token)))`, unpadded, as a JWT claim value
 * must be. The digest is over the token *as transmitted*: the token is an
 * opaque string to this layer, so no decoding or normalisation happens.
 */
export declare const computeAth: (accessToken: string) => Promise<string>;
/**
 * Whether a proof's `ath` binds it to this access token.
 *
 * Compared in constant time. The value is not a secret — an attacker holding
 * the token can compute it — but the comparison sits on a path an attacker can
 * drive with chosen input, and a short-circuiting compare there is the kind of
 * thing that is cheap to avoid and awkward to explain later.
 */
export declare const athMatches: (ath: string, accessToken: string) => Promise<boolean>;
//# sourceMappingURL=ath.d.mts.map