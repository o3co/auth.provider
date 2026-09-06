/**
 * `mode = "full-pki"` — RFC 5280 path validation with revocation, for issue
 * #341.
 *
 * ### Why this is not an extension of `pki.mts`
 *
 * The narrow mode in `pki.mts` is a synchronous hand-written walk that checks
 * what `node:crypto`'s `X509Certificate` happens to expose. Everything left
 * on #341's list — name constraints, the policy tree, `keyUsage` bits,
 * unrecognised critical extensions — needs the DER that class does not
 * surface, and revocation needs a fetch, which a synchronous function cannot
 * do. Both walls are hit at once, and RFC 8705 §7.5 says to delegate rather
 * than climb them: this arm hands path validation to `pkijs`, whose
 * `CertificateChainValidationEngine` implements RFC 5280 §6 including the
 * policy tree and name-constraint processing.
 *
 * The narrow mode is untouched. A deployment on `mode = "pki"` gets exactly
 * the behaviour it had.
 *
 * ### What this module owns, and why it is not all delegated
 *
 * Three things the engine does not do, in ascending order of how badly they
 * fail:
 *
 *  1. **`pathLenConstraint` (RFC 5280 §4.2.1.9).** Not implemented by the
 *     engine. Checked here against the validated path.
 *  2. **Algorithm policy (§6.1.4).** Left to local policy by the RFC, which
 *     in practice means the OpenSSL build's policy. Applied here to every
 *     certificate on the path.
 *  3. **Revocation.** The engine skips its revocation block entirely when
 *     handed no CRLs, and returns *valid*. So a CRL endpoint that is down
 *     produces the same verdict as a certificate that is not revoked. That is
 *     the single most dangerous default in this area, and it is the reason
 *     revocation is decided here, per certificate, rather than by one engine
 *     call with some CRLs attached.
 *
 * ### Why the engine validates the path but does not decide revocation
 *
 * Pass 1 hands the engine the presented chain with no revocation material and
 * takes back the validated path. Pass 2 walks that path — anchor excluded —
 * and, for each certificate, asks the resolver for the CRL its issuer
 * published and checks the serial against it. The resolver has already
 * verified the CRL's signature against that issuer (`crl.mts`), so the
 * lookup is one comparison and the engine is not consulted again.
 *
 * It used to be. The engine takes CRLs as one flat list and applies one rule
 * to the whole path: a certificate with no usable CRL is refused whenever
 * its issuer advertises a distribution point, regardless of
 * `passedWhenNotRevValues`. That is the wrong shape for an operator policy
 * meant to apply per certificate — with the leaf's distribution point down
 * and the intermediate's up, the common outage, `"allow"` refused — and it
 * meant a CRL the engine discarded for a bad signature never reached the
 * logged availability branch. Deciding here makes `on-unavailable` mean what
 * the configuration says: `"reject"` refuses on the first certificate whose
 * status is unknown, `"allow"` skips exactly those certificates and logs each
 * one, and a status that *was* determined as revoked is refused under both.
 *
 * The ordering — validate, then fetch — is a security property, not an
 * optimisation. A distribution point is a URL inside a certificate, and
 * fetching it makes this process issue a request to a destination someone
 * else chose. Validating first means only a certificate that already chains
 * to a configured trust anchor can cause an outbound request at all — an
 * arbitrary certificate presented by an arbitrary client cannot.
 * `fetchGuard.mts` holds the second layer.
 *
 * ### What is still not here
 *
 * OCSP (RFC 6960) is not implemented, and `revocation.mode` refuses to name
 * it rather than accepting the value and ignoring it. Note also that the
 * "stapled OCSP is the cheap path under `tls-layer`" idea in #341 does not
 * survive contact with Node: `status_request` stapling covers the *server's*
 * certificate, and Node exposes no stapled response for a **client**
 * certificate on the server side. An OCSP arm would therefore be
 * responder-fetch only, with the same guards as CRL fetching.
 */
import { X509Certificate } from "node:crypto";
import { type AlgorithmPolicy } from "./algorithms.mjs";
export interface Logger {
    warn(obj: Record<string, unknown>, msg: string): void;
    debug?(obj: Record<string, unknown>, msg: string): void;
}
/**
 * What to do when revocation status cannot be determined.
 *
 * There is no default. "The CRL endpoint is unreachable" and "the certificate
 * is not revoked" are different facts, and which one a deployment is willing
 * to act on depends on whether an outage that blocks logins is worse than a
 * window in which a revoked certificate still works. A library that picks for
 * the operator picks wrong for half of them, silently.
 */
export type OnRevocationUnavailable = "reject" | "allow";
export type RevocationPolicy = {
    readonly mode: "disabled";
} | {
    readonly mode: "crl";
    readonly onUnavailable: OnRevocationUnavailable;
    readonly allowedHosts: readonly string[];
    readonly fetchTimeoutMs: number;
    readonly cacheTtlSeconds: number;
    readonly maxResponseBytes: number;
};
export interface FullPkiOptions {
    readonly trustedCas: readonly X509Certificate[];
    readonly algorithms: AlgorithmPolicy;
    /** Maximum certificates in a path, leaf and anchor included. */
    readonly maxChainDepth: number;
    readonly revocation: RevocationPolicy;
    readonly logger?: Logger;
    /** Injected in tests. */
    readonly fetchImpl?: typeof globalThis.fetch;
}
export type FullPkiResult = {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly step: string;
    readonly detail: string;
};
export interface FullPkiValidator {
    validate(leaf: X509Certificate, chain: readonly X509Certificate[], now: Date): Promise<FullPkiResult>;
    /**
     * Entries in the CRL cache, usable and remembered-unavailable alike.
     * Exposed for tests and for a future cache-size metric.
     */
    readonly crlCacheSize: () => number;
}
export declare const createFullPkiValidator: (options: FullPkiOptions) => FullPkiValidator;
//# sourceMappingURL=validate.d.mts.map