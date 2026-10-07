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
 * A certificate's demand for a stapled OCSP response (RFC 7633), which a client certificate can
 * never meet here: refused under every revocation mode, as is a demand that cannot be decoded.
 */
import * as asn1js from "asn1js";
/** The TLS feature extension (RFC 7633). */
const OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
/** TLS extension types that mean OCSP must-staple (RFC 7633 §4.2.3.1). */
const TLS_FEATURE_STATUS_REQUEST = 5;
const TLS_FEATURE_STATUS_REQUEST_V2 = 17;
/**
 * RFC 7633: a certificate whose TLS feature extension names `status_request`
 * (or `status_request_v2`) demands a stapled OCSP response, which this server
 * cannot present for a client certificate. It is refused under every
 * revocation mode, `disabled` included, since the demand is the
 * certificate's own. Other feature numbers are ignored; an undecodable value
 * is refused whether or not the extension is critical.
 */
export const checkMustStaple = (leaf) => {
    const extension = leaf.extensions?.find((ext) => ext.extnID === OID_TLS_FEATURE);
    if (extension === undefined)
        return { ok: true };
    const unparseable = {
        ok: false,
        step: "unparseable TLS feature extension",
        detail: "the leaf carries a TLS feature extension (RFC 7633) whose value could not be " +
            "decoded, so the requirement it states cannot be honoured",
    };
    const decoded = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
    if (decoded.offset === -1 || !(decoded.result instanceof asn1js.Sequence))
        return unparseable;
    const features = [];
    for (const item of decoded.result.valueBlock.value) {
        if (!(item instanceof asn1js.Integer))
            return unparseable;
        features.push(item.valueBlock.valueDec);
    }
    if (features.includes(TLS_FEATURE_STATUS_REQUEST) ||
        features.includes(TLS_FEATURE_STATUS_REQUEST_V2)) {
        return {
            ok: false,
            step: "OCSP must-staple cannot be satisfied",
            detail: "the leaf carries the TLS feature extension (RFC 7633) requiring status_request, " +
                "and no stapled OCSP response can be presented for a client certificate here — " +
                "the certificate's own requirement cannot be met, so it is refused rather than " +
                "treated as unstapled",
        };
    }
    return { ok: true };
};
