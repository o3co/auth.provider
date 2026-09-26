/** RFC 7636 §4.1: high-entropy URL-safe random string, 43 chars from 32 bytes base64url. */
export declare function generateCodeVerifier(): string;
/** RFC 7636 §4.2: S256 transform — BASE64URL(SHA256(verifier)). */
export declare function codeChallenge(verifier: string): string;
//# sourceMappingURL=pkce.d.mts.map