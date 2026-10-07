/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * The certificate's status as the response states it, and whether the response is current:
 * `thisUpdate` at most `OCSP_CLOCK_SKEW_MS` ahead, and `nextUpdate` (or, without one,
 * `OCSP_UNDATED_RESPONSE_MAX_AGE_MS` after `thisUpdate`) not passed. The answer is used until
 * then, capped by the cache TTL.
 */
import * as asn1js from "asn1js";
/**
 * How far a response's `thisUpdate` may lead this process's clock. Five
 * minutes is the conventional allowance; a responder signing on demand must
 * not be refused for a clock a few seconds ahead, and a response dated
 * further ahead than this is not describing the present.
 */
export const OCSP_CLOCK_SKEW_MS = 5 * 60_000;
/**
 * How long a response with no `nextUpdate` is used for, from its
 * `thisUpdate`. RFC 6960 §4.2.2.1: absence means newer information is
 * available all the time — an instruction to ask again soon, not a licence
 * to keep the answer. Ten minutes absorbs the skew allowance twice over and
 * stays in the same order of magnitude as the negative window.
 */
export const OCSP_UNDATED_RESPONSE_MAX_AGE_MS = 10 * 60_000;
/** `CRLReason` names (RFC 5280 §5.3.1), for the audit trail. */
const CRL_REASON_NAMES = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
};
/** `CertStatus ::= CHOICE { good [0], revoked [1] RevokedInfo, unknown [2] }` (RFC 6960 §4.2.1). */
export const decodeStatus = (certStatus) => {
    if (!(certStatus instanceof asn1js.BaseBlock) || certStatus.idBlock.tagClass !== 3) {
        return { ok: false, detail: "certStatus is not a context-specific CHOICE" };
    }
    switch (certStatus.idBlock.tagNumber) {
        case 0:
            return { ok: true, status: { status: "good" } };
        case 2:
            return { ok: true, status: "unknown" };
        case 1: {
            const values = certStatus instanceof asn1js.Constructed ? certStatus.valueBlock.value : [];
            const time = values[0];
            if (!(time instanceof asn1js.GeneralizedTime)) {
                return { ok: false, detail: "RevokedInfo carries no revocationTime" };
            }
            let reason;
            const reasonBlock = values[1];
            if (reasonBlock instanceof asn1js.Constructed && reasonBlock.idBlock.tagNumber === 0) {
                const enumerated = reasonBlock.valueBlock.value[0];
                if (enumerated instanceof asn1js.Enumerated) {
                    const code = enumerated.valueBlock.valueDec;
                    reason = CRL_REASON_NAMES[code] ?? `reason ${code}`;
                }
            }
            return { ok: true, status: { status: "revoked", revokedAt: time.toDate(), reason } };
        }
        default:
            return {
                ok: false,
                detail: `certStatus tag [${certStatus.idBlock.tagNumber}] is not good, revoked or unknown`,
            };
    }
};
export const freshness = (single, now, cacheTtlSeconds) => {
    const thisUpdate = single.thisUpdate.getTime();
    if (thisUpdate > now.getTime() + OCSP_CLOCK_SKEW_MS) {
        return {
            ok: false,
            reason: "not_yet_valid",
            detail: `the response's thisUpdate ${single.thisUpdate.toISOString()} is in the future`,
        };
    }
    const nextUpdate = single.nextUpdate?.getTime();
    const usableUntil = nextUpdate ?? thisUpdate + OCSP_UNDATED_RESPONSE_MAX_AGE_MS;
    if (usableUntil <= now.getTime()) {
        return {
            ok: false,
            reason: "stale",
            detail: nextUpdate === undefined
                ? `the response carries no nextUpdate and its thisUpdate ${single.thisUpdate.toISOString()} ` +
                    `is older than ${OCSP_UNDATED_RESPONSE_MAX_AGE_MS / 1000}s (RFC 6960 §4.2.2.1)`
                : `the response's nextUpdate ${new Date(nextUpdate).toISOString()} has passed`,
        };
    }
    return { ok: true, expiresAt: Math.min(usableUntil, now.getTime() + cacheTtlSeconds * 1000) };
};
