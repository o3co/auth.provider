/**
 * Compute the RFC 8705 §3.1 certificate thumbprint from the DER-encoded
 * leaf certificate.
 *
 * The thumbprint is `base64url(SHA-256(der))` with trailing `=` pad
 * characters stripped — the RFC 8705 §3.1 normative requirement is:
 *   "The base64url-encoded value MUST omit all trailing pad '=' characters."
 *
 * This value is placed in `cnf.x5t#S256` on the issued access token and (for
 * public clients) on the issued refresh token (RFC 8705 §4 SHOULD).
 *
 * Per Wave 2 Phase 3 spec §6.6 + RFC 8705 §3.1.
 */
export declare const computeCertThumbprint: (der: Uint8Array) => string;
//# sourceMappingURL=thumbprint.d.mts.map