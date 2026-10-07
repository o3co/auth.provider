import type * as pkijs from "pkijs";
import type { OcspCertificateStatus } from "./ocspAnswer.mjs";
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
export type DecodedStatus = {
    readonly ok: true;
    readonly status: OcspCertificateStatus | "unknown";
} | {
    readonly ok: false;
    readonly detail: string;
};
/** `CertStatus ::= CHOICE { good [0], revoked [1] RevokedInfo, unknown [2] }` (RFC 6960 §4.2.1). */
export declare const decodeStatus: (certStatus: unknown) => DecodedStatus;
export type Freshness = {
    readonly ok: true;
    readonly expiresAt: number;
} | {
    readonly ok: false;
    readonly reason: "not_yet_valid" | "stale";
    readonly detail: string;
};
export declare const freshness: (single: pkijs.SingleResponse, now: Date, cacheTtlSeconds: number) => Freshness;
//# sourceMappingURL=ocspStatus.d.mts.map