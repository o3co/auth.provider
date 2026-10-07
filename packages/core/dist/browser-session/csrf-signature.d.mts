/**
 * The bounds of a CSRF token's signature, part of the `csrfTokenSigner`
 * contract: `sign` answers base64url of this many characters, the contract
 * suite holds a signer to it, and a consumer that builds tokens over a signer
 * reads the same two numbers.
 */
/**
 * The fewest characters a signature carries: 22 base64url characters are 132
 * bits, the fewest that reach 128, so a guessed signature passes once in at
 * least 2^128 tries.
 */
export declare const CSRF_SIGNATURE_MIN_LENGTH = 22;
/**
 * The most characters a signature carries: a token (`<expiry>.<nonce>.<signature>`)
 * then stays far inside the 4096 bytes a browser keeps of a cookie.
 */
export declare const CSRF_SIGNATURE_MAX_LENGTH = 512;
//# sourceMappingURL=csrf-signature.d.mts.map