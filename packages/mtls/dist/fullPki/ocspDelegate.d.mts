/**
 * A delegated responder's own revocation status (RFC 6960 §4.2.2.2.1): exempt only when its
 * certificate carries `id-pkix-ocsp-nocheck` as a DER `NULL`, otherwise checked through the
 * caller's source, and taken as `responderUnchecked` when there is none.
 */
import type * as pkijs from "pkijs";
import type { OcspUnavailableReason } from "./ocspAnswer.mjs";
/** What {@link ResponderRevocationCheck} learned about a delegated responder's certificate. */
export type ResponderRevocationOutcome = {
    readonly kind: "determined";
}
/** The CA named no source for the responder's certificate (§4.2.2.2.1, third option): local policy decides, which is to take the answer and report `responderUnchecked`. */
 | {
    readonly kind: "unspecified";
} | {
    readonly kind: "revoked";
    readonly detail: string;
} | {
    readonly kind: "unavailable";
    readonly reason: string;
    readonly detail: string;
    readonly cause?: unknown;
    /** The source for the responder's status did not answer usefully. */
    readonly outage?: true;
};
export type ResponderRevocationCheck = (responder: pkijs.Certificate, issuer: pkijs.Certificate, now: Date) => Promise<ResponderRevocationOutcome>;
/**
 * Whether a delegated responder's certificate carries `id-pkix-ocsp-nocheck`
 * with the DER `NULL` value RFC 6960 §4.2.2.2.1 specifies. Any other value
 * buys no exemption: it is not a statement the CA wrote.
 */
export declare const hasNoCheck: (certificate: pkijs.Certificate) => boolean;
/** What a delegated responder's own status allows: its answer, flagged when unchecked, or a refusal. */
export type ResponderVerdict = {
    ok: true;
    unchecked: boolean;
} | {
    ok: false;
    reason: OcspUnavailableReason;
    detail: string;
    cause?: unknown;
    outage?: true;
};
/**
 * A delegated responder's own certificate. RFC 6960 §4.2.2.2.1 lets a
 * client skip this only for a responder carrying `id-pkix-ocsp-nocheck`;
 * otherwise it is checked through the source the caller wired — the CA's
 * CRL, which the responder cannot answer for itself. A revoked responder's
 * `good` is worth nothing. With no source wired, or none the CA named, the
 * answer is taken and the deviation reported. Called when the answer is
 * built and on every cache hit, since the cached status outlives the check.
 */
export declare const checkDelegateRevocation: (options: {
    readonly responderRevocation?: ResponderRevocationCheck;
}, delegate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date) => Promise<ResponderVerdict>;
//# sourceMappingURL=ocspDelegate.d.mts.map