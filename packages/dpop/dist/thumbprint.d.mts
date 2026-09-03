import { type JWK } from "jose";
/**
 * Compute the JWK Thumbprint (JKT) for a public JWK using SHA-256.
 *
 * RFC 7638 §3 canonical JWK member selection + SHA-256 hash → base64url.
 * Used to bind a DPoP access token to the client's public key per
 * RFC 9449 §6.1 and to derive the `cnf.jkt` claim.
 *
 * Per Wave 2 Phase 2 spec §5.4 + RFC 7638.
 */
export declare const computeJkt: (jwk: JWK) => Promise<string>;
//# sourceMappingURL=thumbprint.d.mts.map