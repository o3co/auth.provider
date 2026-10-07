import * as pkijs from "pkijs";
import { type AlgorithmPolicy } from "./algorithms.mjs";
import { type CriticalExtensionCheck } from "./criticalExtensions.mjs";
import type { GuardedFetch } from "./fetchGuard.mjs";
/**
 * How long a responder that could not be used is remembered, in
 * milliseconds. The CRL resolver's window, for the CRL resolver's reasons.
 */
export declare const OCSP_NEGATIVE_CACHE_TTL_MS = 30000;
/**
 * How far a response's `thisUpdate` may lead this process's clock. Five
 * minutes is the conventional allowance; a responder signing on demand must
 * not be refused for a clock a few seconds ahead, and a response dated
 * further ahead than this is not describing the present.
 */
export declare const OCSP_CLOCK_SKEW_MS: number;
/**
 * How long a response with no `nextUpdate` is used for, from its
 * `thisUpdate`. RFC 6960 §4.2.2.1: absence means newer information is
 * available all the time — an instruction to ask again soon, not a licence
 * to keep the answer. Ten minutes absorbs the skew allowance twice over and
 * stays in the same order of magnitude as the negative window.
 */
export declare const OCSP_UNDATED_RESPONSE_MAX_AGE_MS: number;
/**
 * Why a certificate's status could not be determined by OCSP. Values are
 * stable — audit logs read them. `algorithm_not_permitted` is a response, or
 * a delegated responder's certificate, outside the algorithm policy the path
 * is held to (#470).
 */
export type OcspUnavailableReason = "no_responder" | "fetch_failed" | "unparseable" | "responder_error" | "no_matching_response" | "unsupported_critical_extension" | "algorithm_not_permitted" | "bad_signature" | "nonce_mismatch" | "nonce_missing" | "not_yet_valid" | "stale" | "unknown";
export type OcspCertificateStatus = {
    readonly status: "good";
} | {
    readonly status: "revoked";
    readonly revokedAt: Date;
    /** The `CRLReason` name, when the responder gave one. */
    readonly reason: string | undefined;
};
export type OcspLookup = {
    readonly ok: true;
    /** The responder whose answer this is. */
    readonly responder: string;
    readonly status: OcspCertificateStatus;
} | {
    readonly ok: false;
    readonly reason: OcspUnavailableReason;
    readonly detail: string;
};
export type OcspResponders = {
    readonly ok: true;
    readonly urls: readonly string[];
} | {
    readonly ok: false;
    readonly reason: "no_responder";
    readonly detail: string;
};
/**
 * The OCSP responders a certificate advertises, in the order listed. RFC
 * 5280 §4.2.2.1 lets a CA list several; they are tried in turn until one
 * yields an answer that can be used. Only absolute HTTP(S) URIs are kept —
 * a certificate left with none is `no_responder`, the OCSP twin of
 * `no_distribution_point`: an honest "cannot check", not a silent pass.
 */
export declare const ocspResponders: (certificate: pkijs.Certificate) => OcspResponders;
/**
 * RFC 7633: a certificate carrying the TLS feature extension with
 * `status_request` (or `status_request_v2`) requires a stapled OCSP response
 * in the handshake it is used in. Node presents no stapled response for a
 * client certificate, so the requirement cannot be met by this server, and
 * the certificate is refused — under every revocation mode, `disabled`
 * included, because the demand is the certificate's own, not the
 * operator's. Other feature numbers name nothing this validator can judge
 * and are ignored; a value that cannot be decoded is a demand that cannot
 * be read, and is refused whether or not the extension is critical.
 */
export declare const checkMustStaple: (leaf: pkijs.Certificate) => CriticalExtensionCheck;
export interface OcspResolverOptions {
    readonly fetch: GuardedFetch;
    /**
     * Upper bound on how long an answer is reused, in seconds. The response's
     * own `nextUpdate` still wins when it is sooner.
     */
    readonly cacheTtlSeconds: number;
    /**
     * The signature-algorithm and key-size policy the validated path is held
     * to, applied to the response's signature and to a delegated responder's
     * certificate as well (#470). See the module header.
     *
     * Optional, defaulting to `DEFAULT_ALGORITHM_POLICY` — the same strict
     * policy the config resolves to when the operator sets nothing. This is
     * a security fix on a public interface, so a consumer who constructs a
     * resolver directly and upgrades without touching their code must *get*
     * the fix rather than opt into it. The default is fail-closed: omitting
     * the field can only make the check stricter, never weaker, so no
     * existing caller is silently left unprotected. `validate.mts` passes
     * the operator's configured policy explicitly.
     */
    readonly algorithms?: AlgorithmPolicy;
    /**
     * Refuse a response that does not carry the request's nonce. Defaults to
     * `true`; see the module header for what `false` gives up.
     */
    readonly requireNonce?: boolean;
    /** Bound on cache size. Entries are per certificate, so the default is roomier than the CRL cache's. */
    readonly maxCacheEntries?: number;
}
export interface OcspResolver {
    /**
     * Ask the responders `certificate` names about it, verifying each answer
     * against `issuer`, the certificate that issued it — the next element up
     * the validated path. Only an answer whose signer is that issuer, or a
     * responder that issuer delegated to, is ever returned or cached.
     */
    resolve(certificate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date): Promise<OcspLookup>;
    /** Entry count, usable and remembered-unavailable alike — for tests and for a future metric. */
    size(): number;
}
export declare const createOcspResolver: (options: OcspResolverOptions) => OcspResolver;
//# sourceMappingURL=ocsp.d.mts.map