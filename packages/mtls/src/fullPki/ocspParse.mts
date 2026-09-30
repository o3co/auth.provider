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
 * Decoding a responder's answer: a DER `OCSPResponse` whose status is `successful` and whose
 * bytes are an `id-pkix-ocsp-basic` response. Anything else is `unparseable` or
 * `responder_error`; nothing the response says is trusted yet.
 */

import * as pkijs from "pkijs";

/** `id-pkix-ocsp-basic` response type (RFC 6960 §4.2.1). */
const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

/** `OCSPResponseStatus` names (RFC 6960 §4.2.1). */
const RESPONSE_STATUS_NAMES: Readonly<Record<number, string>> = {
	0: "successful",
	1: "malformedRequest",
	2: "internalError",
	3: "tryLater",
	5: "sigRequired",
	6: "unauthorized",
};

export type Parsed =
	| { readonly ok: true; readonly basic: pkijs.BasicOCSPResponse }
	| {
			readonly ok: false;
			readonly reason: "unparseable" | "responder_error";
			readonly detail: string;
			readonly cause?: unknown;
	  };

export const parseResponse = (bytes: Uint8Array): Parsed => {
	let response: pkijs.OCSPResponse;
	try {
		response = pkijs.OCSPResponse.fromBER(bytes);
	} catch (err) {
		return {
			ok: false,
			reason: "unparseable",
			detail: "not a DER OCSPResponse",
			cause: err,
		};
	}
	const status = response.responseStatus.valueBlock.valueDec;
	if (status !== 0) {
		return {
			ok: false,
			reason: "responder_error",
			detail: `the responder answered ${RESPONSE_STATUS_NAMES[status] ?? "status"} (${status})`,
		};
	}
	const responseBytes = response.responseBytes;
	if (responseBytes === undefined) {
		return {
			ok: false,
			reason: "unparseable",
			detail: "a successful response with no responseBytes",
		};
	}
	if (responseBytes.responseType !== OID_OCSP_BASIC) {
		return {
			ok: false,
			reason: "unparseable",
			detail: `responseType ${responseBytes.responseType} is not id-pkix-ocsp-basic`,
		};
	}
	try {
		return {
			ok: true,
			basic: pkijs.BasicOCSPResponse.fromBER(responseBytes.response.valueBlock.valueHexView),
		};
	} catch (err) {
		return {
			ok: false,
			reason: "unparseable",
			detail: "not a DER BasicOCSPResponse",
			cause: err,
		};
	}
};
