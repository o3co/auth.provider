import type { X509Certificate } from "node:crypto";
/**
 * Narrow PKI mode chain validation per Wave 2 Phase 3 spec §7.2.
 *
 * **This is NOT full RFC 5280 path validation.** The narrow mode checks:
 *
 *   1. Leaf cert validity window (`notBefore <= now <= notAfter`).
 *   2. Chain walk hop-by-hop, with fingerprint cycle detection.
 *   3. Per-intermediate validity window.
 *   4. Per-intermediate `basicConstraints.CA === true` (RFC 5280 §4.2.1.9).
 *   5. Per-hop **pair check**: `checkIssued` (DN / AKID / SKID match) AND
 *      `isSignedBy` (cryptographic signature). Applied at both intermediate
 *      hops and the terminal trust anchor — see `isSignedBy`'s JSDoc for why
 *      both are required.
 *   6. Trust-anchor validity window.
 *
 * The narrow mode is sufficient for the common single-private-CA M2M
 * deployment shape (RFC 8705 §2.1). Operators needing full path validation
 * (name constraints, policy mappings, CRL/OCSP, path length) MUST defer
 * deployment until `mode = "full-pki"` arm ships — README §"PKI Mode Scope"
 * documents the scope-out, and `mtlsModule` boot-time check rejects
 * misconfigurations that would silently fail.
 *
 * **Why explicit boolean return, not throw**: the call site (extractor.mts
 * step 5) wraps the failure into `MtlsError("chain_validation_failed", ...)`.
 * Threading `{ ok, step }` lets the extractor populate the audit `detail`
 * field with the specific failing check name without parsing an exception
 * message. Mirrors `parseProof` from `@o3co/auth-provider-dpop`.
 *
 * Per spec §7.2 + §7.3 (checks NOT performed) + §7.4 (RFC 8705 §7.4 alignment).
 */
type ValidationResult = {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly step: string;
};
export declare const validateCertChain: (leaf: X509Certificate, intermediates: readonly X509Certificate[], trustedCas: readonly X509Certificate[], now: Date) => ValidationResult;
export {};
//# sourceMappingURL=pki.d.mts.map