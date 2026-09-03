/**
 * Parsed leaf certificate with DER bytes, optional chain, and diagnostic
 * metadata populated from `node:crypto`'s `X509Certificate`.
 *
 * The `der` field is the canonical source of truth for thumbprinting per
 * RFC 8705 §3.1: `SHA-256(der)` → `cnf.x5t#S256`.
 *
 * The `parsed` sub-object is a diagnostic convenience — field names mirror
 * the `X509Certificate` property names, serialized as ISO-8601 / RFC 5280
 * GeneralizedTime strings for logging and audit emission.
 *
 * Per Wave 2 Phase 3 spec §5.3.
 */
export interface ClientCertificate {
    /** DER-encoded leaf certificate bytes — the thumbprint input. */
    readonly der: Uint8Array;
    /**
     * DER-encoded intermediate certificates in presentation order (leaf's
     * issuer first, root-CA-signed last). Populated from the XFCC `Chain=`
     * parameter when source is `"header"` + dialect `"envoy"`.
     */
    readonly chain?: readonly Uint8Array[];
    /** Diagnostic fields populated by `X509Certificate` — NOT used for trust decisions. */
    readonly parsed: {
        readonly subject: string;
        readonly issuer: string;
        /** ISO-8601 string from `X509Certificate.validFrom` */
        readonly notBefore: string;
        /** ISO-8601 string from `X509Certificate.validTo` */
        readonly notAfter: string;
    };
}
/**
 * Parse DER bytes into a `ClientCertificate`, optionally attaching intermediate
 * chain DER entries.
 *
 * Uses `new X509Certificate(der)` from `node:crypto` (Node ≥ 15.6) per
 * RFC 8705 §7.5's mandate to use an established X.509 library rather than
 * a custom parser.
 *
 * Throws a plain `Error` on parse failure — the call site (extractor.mts
 * step 3) wraps it into `MtlsError("cert_decode_failed", …)`.
 *
 * Per Wave 2 Phase 3 spec §5.3 + §6.3.
 */
export declare const parseDerToCertificate: (der: Uint8Array, chain?: readonly Uint8Array[]) => ClientCertificate;
//# sourceMappingURL=certificate.d.mts.map