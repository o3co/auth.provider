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
 * What a response is shaped like, judged before its signature as in `crl.mts`: a single response
 * matching the certificate's `CertID`, no unprocessed critical extension, and a signature
 * algorithm the path's policy allows (pkijs accepts SHA-1). Each can only refuse, so a refusal
 * is remembered per certificate.
 */
import * as pkijs from "pkijs";
import { checkSignatureAlgorithm } from "./algorithms.mjs";
import { checkOcspCriticalExtensions } from "./criticalExtensions.mjs";
/** SHA-1, the `CertID` hash. */
const OID_SHA1 = "1.3.14.3.2.26";
/**
 * The single response about `certificate`, matched by `CertID`. The request
 * asked by SHA-1; a responder that answers by another hash is matched by
 * recomputing the `CertID` with that hash rather than refused on the OID —
 * both name the same issuer and serial.
 */
const findSingleResponse = async (basic, certificate, issuer, requested, crypto) => {
    const byAlgorithm = new Map([[OID_SHA1, requested]]);
    for (const single of basic.tbsResponseData.responses) {
        const oid = single.certID.hashAlgorithm.algorithmId;
        let ours = byAlgorithm.get(oid);
        if (ours === undefined) {
            ours = null;
            try {
                const algorithm = crypto.getAlgorithmByOID(oid, true, "CertID.hashAlgorithm");
                ours = await pkijs.CertID.create(certificate, { hashAlgorithm: algorithm.name, issuerCertificate: issuer }, crypto);
            }
            catch {
                // A hash this engine does not speak cannot identify anything here.
            }
            byAlgorithm.set(oid, ours);
        }
        if (ours !== null && single.certID.isEqual(ours))
            return single;
    }
    return undefined;
};
/**
 * The response's shape, in order: the single response matching `requested`, then critical
 * extensions, then the response's signature algorithm.
 */
export const checkResponseShape = async (basic, certificate, issuer, requested, crypto, algorithms) => {
    const single = await findSingleResponse(basic, certificate, issuer, requested, crypto);
    if (single === undefined) {
        return {
            ok: false,
            reason: "no_matching_response",
            detail: "the response carries no single response for this certificate's CertID",
        };
    }
    const critical = checkOcspCriticalExtensions(basic.tbsResponseData.responseExtensions ?? [], single.singleExtensions ?? []);
    if (!critical.ok) {
        return { ok: false, reason: "unsupported_critical_extension", detail: critical.detail };
    }
    // The response's own signature algorithm, still on shape alone, judged
    // before its signer is identified and remembered per certificate (see
    // the module header). A responder certificate is held to the full
    // policy inside `identifySigner`.
    const algorithm = checkSignatureAlgorithm(basic.signatureAlgorithm.algorithmId, algorithms);
    if (!algorithm.ok) {
        return {
            ok: false,
            reason: "algorithm_not_permitted",
            detail: `the response's signature algorithm ${algorithm.detail}`,
        };
    }
    return { ok: true, single };
};
