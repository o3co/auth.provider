/**
 * Server-provided DPoP nonces (RFC 9449 §8 / §9, #530).
 *
 * Without a nonce the only freshness control on a proof is `iat` skew, which
 * is weak for a token that lives longer than a few minutes: a proof minted
 * ahead of time stays usable for the whole window. A nonce the server hands
 * out and the client has to echo bounds pre-generation to the nonce's own
 * lifetime instead.
 *
 * ## Stateless by construction
 *
 * A nonce is `<bucket>.<mac>`: the current time bucket and an HMAC over it
 * under a secret every replica shares. Verifying one is recomputing the MAC,
 * so nothing is stored and nothing is looked up — a nonce minted by one
 * replica verifies on every other, and there is no store to be unavailable
 * on the proof path. The cost is that a nonce is not single-use; it is not
 * meant to be — replay of the *proof* is what `jti` and the replay store
 * refuse, and the nonce only says "this proof was made after this instant".
 *
 * ## Rotation
 *
 * The bucket advances every `ttlSeconds`. A nonce from the current bucket or
 * the previous one is accepted, so a client that received a nonce just before
 * the boundary is not refused a moment later; one two buckets old is. Every
 * response carries the current nonce (`DPoP-Nonce`), which is how the client
 * learns of the rotation before its next proof.
 */
export interface DPoPNonceIssuer {
    /** The nonce for right now. */
    issue(): string;
    /** Whether `nonce` is one this server issued within the acceptance window. */
    verify(nonce: string): boolean;
}
export interface DPoPNonceIssuerOptions {
    /**
     * Shared by every replica. At least 32 bytes of key material: a string is
     * measured on its decoded length, as core's secret floor measures every
     * operator secret, so 32 hex characters are 16 bytes and refused.
     */
    readonly secret: string | Uint8Array;
    /** How often the nonce rotates; the acceptance window is twice this. Default 300 s. */
    readonly ttlSeconds?: number;
    /** Test seam. */
    readonly now?: () => number;
}
export declare const DEFAULT_DPOP_NONCE_TTL_SECONDS = 300;
export declare function createDPoPNonceIssuer(options: DPoPNonceIssuerOptions): DPoPNonceIssuer;
//# sourceMappingURL=nonce.d.mts.map