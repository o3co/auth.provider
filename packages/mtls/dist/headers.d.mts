/**
 * Header dialect parsers for extracting client certificate PEM from reverse-
 * proxy forwarded-cert headers.
 *
 * Two dialects ship in Phase 3 Stage 1 per spec §1.3:
 *   - `"envoy"`: Envoy XFCC (x-forwarded-client-cert) header format.
 *   - `"plain-pem"`: Raw PEM value, possibly URL-encoded.
 *
 * Both parsers are internal — NOT re-exported from index.mts. Consumers
 * select a dialect via the `certHeaderDialect` config key; `createMtlsMechanism`
 * dispatches to the correct parser at extraction time.
 *
 * Per Wave 2 Phase 3 spec §5.4 (CertHeaderDialect) + §6.2 (step 2 — dialect parse).
 */
/**
 * The set of supported certificate header dialect identifiers.
 *
 * Exported from index.mts per spec §5.1 so operators can reference the type
 * when building typed config objects. The union is closed at Stage 1 — a
 * future nginx dialect adds a new arm via a semver-minor bump, not a
 * catch-all `string`.
 *
 * Per Wave 2 Phase 3 spec §5.4.
 */
export type CertHeaderDialect = "envoy" | "plain-pem";
/** Structured output from both dialect parsers. */
interface ParsedCertHeader {
    /** PEM-encoded leaf certificate (already URL-decoded if applicable). */
    readonly certPem: string;
    /** PEM-encoded intermediate chain (XFCC `Chain=` value). Absent in plain-PEM dialect. */
    readonly chainPem?: string;
}
/**
 * Parse an Envoy XFCC (x-forwarded-client-cert) header value.
 *
 * XFCC grammar (simplified from Envoy docs):
 *   XFCC = element *("," element)
 *   element = field *(";" field)
 *   field = token "=" value
 *
 * Phase 3 Stage 1 processes only the FIRST element (the client-facing hop).
 * Required field: `Cert=<url-encoded-pem>`. Optional field: `Chain=<url-encoded-pem>`.
 * `By=` and `Hash=` are parsed-past but not used — they are informational.
 *
 * Parse failure → throws a plain `Error`. The call site (extractor.mts step 2)
 * wraps it into `MtlsError("malformed_header", "envoy XFCC parse failure: <detail>")`.
 *
 * Per Wave 2 Phase 3 spec §6.2.
 */
export declare const parseEnvoyXfccHeader: (value: string) => ParsedCertHeader;
/**
 * Parse a plain-PEM certificate header.
 *
 * The header value is either a literal PEM block or a URL-percent-encoded
 * PEM block. URL-encoded values are decoded automatically.
 *
 * **Multi-PEM concatenation is rejected** (spec OQ1 §14.1 strict decision):
 * a header value containing multiple `-----BEGIN CERTIFICATE-----` blocks is
 * malformed_header. Operators who need to convey a chain MUST use the `envoy`
 * dialect with its `Chain=` field instead.
 *
 * Parse failure → throws a plain `Error`. The call site wraps it into
 * `MtlsError("malformed_header", …)`.
 *
 * Per Wave 2 Phase 3 spec §6.2 + OQ1 §14.1.
 */
export declare const parsePlainPemHeader: (value: string) => ParsedCertHeader;
export {};
//# sourceMappingURL=headers.d.mts.map