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
 * Where a certificate says to ask about it: the `id-ad-ocsp` HTTP(S) URIs in its
 * `authorityInfoAccess`, in the order listed. A certificate naming none is `no_responder`,
 * never a pass.
 */

import type * as pkijs from "pkijs";
import { GENERAL_NAME_URI, isHttpUrl } from "./revocationSource.mjs";

/** OID of `authorityInfoAccess` (RFC 5280 §4.2.2.1). */
const OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
/** `id-ad-ocsp` access method. */
const OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";

export type OcspResponders =
	| { readonly ok: true; readonly urls: readonly string[] }
	| { readonly ok: false; readonly reason: "no_responder"; readonly detail: string };

/**
 * The OCSP responders a certificate advertises, in the order listed. RFC
 * 5280 §4.2.2.1 lets a CA list several; they are tried in turn until one
 * yields an answer that can be used. Only absolute HTTP(S) URIs are kept —
 * a certificate left with none is `no_responder`, the OCSP twin of
 * `no_distribution_point`: an honest "cannot check", not a silent pass.
 */
export const ocspResponders = (certificate: pkijs.Certificate): OcspResponders => {
	const extension = certificate.extensions?.find((ext) => ext.extnID === OID_AUTHORITY_INFO_ACCESS);
	const parsed = extension?.parsedValue as pkijs.InfoAccess | undefined;
	const urls = (parsed?.accessDescriptions ?? [])
		.filter((description) => description.accessMethod === OID_AD_OCSP)
		.filter((description) => description.accessLocation.type === GENERAL_NAME_URI)
		.map((description) => description.accessLocation.value)
		.filter((value): value is string => typeof value === "string" && isHttpUrl(value));
	if (urls.length === 0) {
		return {
			ok: false,
			reason: "no_responder",
			detail: "certificate advertises no id-ad-ocsp HTTP(S) URI in authorityInfoAccess",
		};
	}
	return { ok: true, urls };
};
