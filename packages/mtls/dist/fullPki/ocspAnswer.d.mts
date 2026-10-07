/**
 * What an OCSP lookup answers: a status, or why none could be determined, with `reason`,
 * `detail` and `cause` as in `crl.mts`. A failure is an `outage` when the responder did not
 * answer usefully: `isSourceFailure`, `unparseable`, `responder_error`, `stale`, or a delegated
 * responder's status unreadable for such a reason.
 */
import type * as pkijs from "pkijs";
/**
 * Why a certificate's status could not be determined by OCSP. Values are
 * stable — audit logs read them. `algorithm_not_permitted` is a response, or
 * a delegated responder's certificate, outside the path's algorithm policy.
 */
export type OcspUnavailableReason = "no_responder" | "fetch_failed" | "unparseable" | "responder_error" | "no_matching_response" | "unsupported_critical_extension" | "algorithm_not_permitted" | "bad_signature" | "nonce_mismatch" | "nonce_missing" | "not_yet_valid" | "stale" | "unknown" | "responder_revoked" | "responder_status_unavailable";
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
    /**
     * The answer came from a delegated responder whose certificate lacks
     * `id-pkix-ocsp-nocheck`, and no `responderRevocation` source could
     * check it — RFC 6960 §4.2.2.2.1's local-policy deviation, for the
     * caller to log.
     */
    readonly responderUnchecked?: boolean;
} | {
    readonly ok: false;
    readonly reason: OcspUnavailableReason;
    readonly detail: string;
    /** The last failure's library error, beside its `reason`, when one threw. */
    readonly cause?: unknown;
    /** Every responder that was asked failed as an outage (see the module header). */
    readonly outage?: true;
    /**
     * Each responder that was asked and could not be used, when the
     * certificate named any: what a caller that reports every source one
     * by one reads.
     */
    readonly responders?: readonly OcspResponderUnavailable[];
};
/** One responder that was asked and could not be used, and why. */
export interface OcspResponderUnavailable {
    readonly url: string;
    readonly reason: OcspUnavailableReason;
    readonly detail: string;
    readonly cause?: unknown;
    readonly outage?: true;
}
/** What one responder produced for one certificate, after every check. */
export type Answer = {
    readonly ok: true;
    readonly status: OcspCertificateStatus;
    readonly expiresAt: number;
    /** A delegated responder without `nocheck`, taken because no source could check it. */
    readonly responderUnchecked?: boolean;
    /**
     * The delegated responder this answer depended on, when its certificate
     * lacks `nocheck`. Cached with the status so every hit re-checks it: a
     * responder revoked after the answer must stop counting.
     */
    readonly delegate?: pkijs.Certificate;
} | {
    readonly ok: false;
    readonly reason: OcspUnavailableReason;
    readonly detail: string;
    readonly cause?: unknown;
    readonly outage?: true;
};
/** `answer`, marked an outage when its reason says the responder did not answer usefully. */
export declare const markOutage: (answer: Answer) => Answer;
//# sourceMappingURL=ocspAnswer.d.mts.map