/**
 * Internal PEM <-> DER codec helpers.
 *
 * These are NOT exported from the package index — consumers never need raw
 * DER bytes directly. The wrapping `MtlsError("cert_decode_failed", …)` is
 * applied by the call site (extractor.mts step 3) so this module stays
 * exception-agnostic, throwing plain `Error` on malformed input.
 *
 * Per Wave 2 Phase 3 spec §4 (package layout) + §6.3 (step 3, PEM→DER decode).
 */
/**
 * Decode a single PEM block to its DER bytes.
 *
 * Accepts standard PEM with `-----BEGIN CERTIFICATE-----` / `-----END
 * CERTIFICATE-----` markers. The base64 body may contain newlines, spaces,
 * or CRLF — all whitespace is stripped before decoding.
 *
 * Throws a plain `Error` on parse failure; the call site wraps it into
 * `MtlsError("cert_decode_failed", …)`.
 *
 * NOTE: URL-encoded PEM (from XFCC `Cert=` values) must be URL-decoded
 * BEFORE calling this function — the dialect parsers in headers.mts own that
 * responsibility (per spec §6.2).
 */
export declare const pemToDer: (pem: string) => Uint8Array;
/**
 * Encode DER bytes back to a PEM string with 64-character line wrapping.
 *
 * The `type` parameter (default `"CERTIFICATE"`) controls the marker label,
 * matching the convention from RFC 7468 §13 for certificate PEM.
 *
 * Per Wave 2 Phase 3 spec §4 (pem.mts internal codec).
 */
export declare const derToPem: (der: Uint8Array, type?: string) => string;
//# sourceMappingURL=pem.d.mts.map