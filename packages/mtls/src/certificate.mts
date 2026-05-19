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
import { X509Certificate } from "node:crypto";

/**
 * Parsed leaf certificate with DER bytes, optional chain, and diagnostic
 * metadata populated from `node:crypto`'s `X509Certificate`.
 *
 * The `der` field is the canonical source of truth for thumbprinting per
 * RFC 8705 §3.1: `SHA-256(der)` → `cnf.x5t#S256`.
 *
 * The `parsed` sub-object is a diagnostic convenience — field names mirror
 * the `X509Certificate` property names, serialized as ISO-8601 / RFC 5280
 * GeneralizedTime strings for logging and audit emission.
 *
 * Per Wave 2 Phase 3 spec §5.3.
 */
export interface ClientCertificate {
	/** DER-encoded leaf certificate bytes — the thumbprint input. */
	readonly der: Uint8Array;
	/**
	 * DER-encoded intermediate certificates in presentation order (leaf's
	 * issuer first, root-CA-signed last). Populated from the XFCC `Chain=`
	 * parameter when source is `"header"` + dialect `"envoy"`.
	 */
	readonly chain?: readonly Uint8Array[];
	/** Diagnostic fields populated by `X509Certificate` — NOT used for trust decisions. */
	readonly parsed: {
		readonly subject: string;
		readonly issuer: string;
		/** ISO-8601 string from `X509Certificate.validFrom` */
		readonly notBefore: string;
		/** ISO-8601 string from `X509Certificate.validTo` */
		readonly notAfter: string;
	};
}

/**
 * Parse DER bytes into a `ClientCertificate`, optionally attaching intermediate
 * chain DER entries.
 *
 * Uses `new X509Certificate(der)` from `node:crypto` (Node ≥ 15.6) per
 * RFC 8705 §7.5's mandate to use an established X.509 library rather than
 * a custom parser.
 *
 * Throws a plain `Error` on parse failure — the call site (extractor.mts
 * step 3) wraps it into `MtlsError("cert_decode_failed", …)`.
 *
 * Per Wave 2 Phase 3 spec §5.3 + §6.3.
 */
export const parseDerToCertificate = (
	der: Uint8Array,
	chain?: readonly Uint8Array[],
): ClientCertificate => {
	// `new X509Certificate(der)` throws DOMException / Error on malformed DER —
	// we let the error propagate unmodified so the call site can wrap it with
	// the correct MtlsReasonCode context.
	const x509 = new X509Certificate(der);

	return {
		der,
		...(chain !== undefined ? { chain } : {}),
		parsed: {
			subject: x509.subject,
			issuer: x509.issuer,
			// `validFrom` / `validTo` are ISO 8601 date strings from Node's X509Certificate.
			notBefore: x509.validFrom,
			notAfter: x509.validTo,
		},
	};
};
