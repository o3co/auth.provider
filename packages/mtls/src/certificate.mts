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
 * Parsed leaf certificate: DER bytes, an optional chain, and diagnostic
 * metadata from `node:crypto`'s `X509Certificate`.
 *
 * `der` is the thumbprint input (RFC 8705 §3.1: `SHA-256(der)` →
 * `cnf.x5t#S256`). `parsed` is for logging and audit only; its field names
 * mirror `X509Certificate`'s properties.
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
 * Parses DER bytes into a `ClientCertificate`, optionally attaching the
 * intermediate chain's DER entries. Uses `node:crypto`'s `X509Certificate`:
 * RFC 8705 §7.5 asks for an established X.509 library, not a custom parser.
 *
 * Throws a plain `Error` on parse failure. No product code calls it; only its
 * tests do.
 */
export const parseDerToCertificate = (
	der: Uint8Array,
	chain?: readonly Uint8Array[],
): ClientCertificate => {
	// `new X509Certificate(der)` throws DOMException / Error on malformed DER —
	// we let the error propagate unmodified so the call site can wrap it with
	// the correct MtlsReasonCode context.
	const x509 = new X509Certificate(der);

	// Defense in depth: copy the DER bytes so a caller holding the input
	// buffer cannot tamper with the thumbprint source after parse. `readonly`
	// on the type protects the property assignment, not the bytes.
	const derCopy = new Uint8Array(der);
	const chainCopy = chain !== undefined ? chain.map((entry) => new Uint8Array(entry)) : undefined;

	return {
		der: derCopy,
		...(chainCopy !== undefined ? { chain: chainCopy } : {}),
		parsed: {
			subject: x509.subject,
			issuer: x509.issuer,
			// `validFrom` / `validTo` are ISO 8601 date strings from Node's X509Certificate.
			notBefore: x509.validFrom,
			notAfter: x509.validTo,
		},
	};
};
