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
 * The OCSP request and what binds an answer to it: a SHA-1 `CertID` (RFC 6960 §4.1.1, a lookup
 * key, not a signature) and a fresh 16-byte nonce (§4.4.1, RFC 8954) the response must echo byte
 * for byte; one echoing none is refused unless the caller allows it, since a captured "good"
 * would otherwise replay until its `nextUpdate`.
 */
import { randomBytes } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { equalBytes } from "./ocspBytes.mjs";
/** `id-pkix-ocsp-nonce` (RFC 6960 §4.4.1). */
const OID_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";
/** RFC 8954 §2.1 bounds the nonce to 1..32 bytes. */
const NONCE_BYTES = 16;
export const buildRequest = async (certificate, issuer, crypto) => {
    const certId = await pkijs.CertID.create(certificate, { hashAlgorithm: "SHA-1", issuerCertificate: issuer }, crypto);
    // A fresh copy: `randomBytes` may hand back a slice of a pooled buffer,
    // and the ASN.1 encoder reads the whole underlying `ArrayBuffer`.
    const random = new Uint8Array(randomBytes(NONCE_BYTES));
    const nonce = new Uint8Array(new asn1js.OctetString({ valueHex: random.buffer }).toBER(false));
    const request = new pkijs.OCSPRequest({
        tbsRequest: new pkijs.TBSRequest({
            requestList: [new pkijs.Request({ reqCert: certId })],
            requestExtensions: [
                new pkijs.Extension({
                    extnID: OID_OCSP_NONCE,
                    critical: false,
                    extnValue: nonce.slice().buffer,
                }),
            ],
        }),
    });
    return { der: new Uint8Array(request.toSchema(true).toBER(false)), certId, nonce };
};
/**
 * Whether `basic` echoes `nonce`, the one the request sent. A response carrying none passes
 * only when `requireNonce` is false.
 */
export const checkNonce = (basic, nonce, requireNonce) => {
    const echoed = basic.tbsResponseData.responseExtensions?.find((ext) => ext.extnID === OID_OCSP_NONCE);
    if (echoed === undefined) {
        if (requireNonce) {
            return {
                ok: false,
                reason: "nonce_missing",
                detail: "the response carries no nonce, so nothing binds it to this request " +
                    "(RFC 6960 §4.4.1; set mtls.fullPki.revocation.ocspRequireNonce = false only for a responder " +
                    "that pre-produces its answers)",
            };
        }
    }
    else if (!equalBytes(echoed.extnValue.valueBlock.valueHexView, nonce)) {
        return {
            ok: false,
            reason: "nonce_mismatch",
            detail: "the response's nonce is not the one this request sent",
        };
    }
    return { ok: true };
};
