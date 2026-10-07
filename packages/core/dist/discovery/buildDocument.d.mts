import type { OidcDiscoveryContribution } from "./types.mjs";
/** Thrown when module `discoveryMetadata` contributions cannot form a valid document. */
export declare class DiscoveryDocumentError extends Error {
    readonly name = "DiscoveryDocumentError";
}
/**
 * Aggregate every module's {@link OidcDiscoveryContribution} into the single
 * OIDC discovery document.
 *
 * The aggregator owns `issuer` (trailing-slash-normalized) and
 * `id_token_signing_alg_values_supported` (from the keyStore). Module
 * contributions supply issuer-relative `endpoints` (prefixed with the issuer
 * here) and literal `metadata` (arrays concatenated + de-duplicated; scalars
 * must agree). Conflicting values, reserved-field contributions, non-absolute
 * endpoint paths, and a document missing any OIDC-required field all throw
 * {@link DiscoveryDocumentError} — surfaced as a boot error so misconfiguration
 * fails fast rather than serving a malformed document.
 *
 * Items are processed in caller-supplied (module-registration) order, so the
 * output is deterministic.
 */
export declare function buildDiscoveryDocument(items: readonly OidcDiscoveryContribution[], opts: {
    readonly issuer: string;
    readonly signingAlgs: readonly string[];
}): Record<string, unknown>;
//# sourceMappingURL=buildDocument.d.mts.map