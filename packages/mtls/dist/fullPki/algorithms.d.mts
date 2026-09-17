/**
 * Signature-algorithm and key-strength policy for `mode = "full-pki"`.
 *
 * RFC 5280 §6.1.4 leaves the acceptable algorithm set to local policy, and
 * without one "acceptable" means "whatever OpenSSL was built to parse". That
 * is not a decision a deployment made; it is a decision its base image made.
 * A certificate signed with SHA-1 still verifies, and a chain is only as
 * strong as its weakest hop — so the policy is applied to **every**
 * certificate on the validated path, anchors included, not just the leaf.
 *
 * Names rather than OIDs in config: an operator reviewing
 * `signature-algorithms` should be able to see what it says. Unknown names
 * fail at boot rather than silently matching nothing, which would leave a
 * deployment believing it had a policy while rejecting every certificate.
 */
import type { X509Certificate } from "node:crypto";
/**
 * The algorithms this module will name. Deliberately a closed set: an
 * operator cannot express "SHA-1 is fine" by pasting an OID, because there is
 * no version of that sentence this module should help write.
 */
export declare const SIGNATURE_ALGORITHM_OIDS: {
    readonly sha256WithRSAEncryption: "1.2.840.113549.1.1.11";
    readonly sha384WithRSAEncryption: "1.2.840.113549.1.1.12";
    readonly sha512WithRSAEncryption: "1.2.840.113549.1.1.13";
    readonly rsassaPss: "1.2.840.113549.1.1.10";
    readonly ecdsaWithSHA256: "1.2.840.10045.4.3.2";
    readonly ecdsaWithSHA384: "1.2.840.10045.4.3.3";
    readonly ecdsaWithSHA512: "1.2.840.10045.4.3.4";
    readonly ed25519: "1.3.101.112";
    readonly ed448: "1.3.101.113";
};
export type SignatureAlgorithmName = keyof typeof SIGNATURE_ALGORITHM_OIDS;
export declare const SIGNATURE_ALGORITHM_NAMES: readonly SignatureAlgorithmName[];
/**
 * The default allowlist: every name above. The default is permissive across
 * *modern* algorithms and closed against everything else — SHA-1 and MD5 are
 * absent because they are not in the map at all, so no configuration can
 * reach them.
 */
export declare const DEFAULT_SIGNATURE_ALGORITHMS: readonly SignatureAlgorithmName[];
export interface AlgorithmPolicy {
    readonly signatureAlgorithms: readonly SignatureAlgorithmName[];
    /** Minimum RSA modulus size in bits. Ignored for EC and EdDSA keys. */
    readonly minRsaKeyBits: number;
}
export type AlgorithmCheck = {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly step: string;
    readonly detail: string;
};
export declare const checkAlgorithmPolicy: (certificate: X509Certificate, signatureAlgorithmOid: string, policy: AlgorithmPolicy) => AlgorithmCheck;
//# sourceMappingURL=algorithms.d.mts.map