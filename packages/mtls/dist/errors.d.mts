/**
 * Granular internal reason code for an mTLS certificate validation failure.
 *
 * The wire-level error code is always `"invalid_certificate"` (see §3.4).
 * This reason field is for internal audit emission only — it MUST NOT be
 * forwarded to the client verbatim (the wire `error_description` may contain
 * a safe, user-facing variant).
 *
 * Per Wave 2 Phase 3 spec §5.5 + §3.4.
 */
export type MtlsReasonCode = "malformed_header" | "unknown_dialect" | "cert_decode_failed" | "cert_expired" | "cert_not_yet_valid" | "chain_validation_failed" | "trusted_cas_unconfigured" | "tls_peer_unavailable";
/**
 * Thrown by the mTLS cert extraction and validation pipeline for any
 * certificate validation failure.
 *
 * Wire-level `code` is hard-coded to `"invalid_certificate"` — the single
 * stable error code Phase 3 emits. The `reason` field carries a granular
 * sub-classification for audit emission; it must never reach the wire
 * verbatim (use a safe error description instead).
 *
 * Per Wave 2 Phase 3 spec §5.5 + design principle §3.4.
 */
export declare class MtlsError extends Error {
    readonly code: "invalid_certificate";
    readonly reason: MtlsReasonCode;
    readonly detail?: Record<string, unknown>;
    constructor(reason: MtlsReasonCode, message: string, detail?: Record<string, unknown>);
}
/**
 * The wire-level OAuth error code emitted by Phase 3 mTLS failures.
 * Always `"invalid_certificate"` — the stable audit + wire surface exported
 * per spec §5.1 so consumers can name the wire-side surface explicitly when
 * constructing error envelopes without importing the class.
 */
export type MtlsErrorCode = MtlsError["code"];
//# sourceMappingURL=errors.d.mts.map