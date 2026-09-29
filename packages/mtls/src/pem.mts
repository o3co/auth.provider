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
 * Internal PEM <-> DER codec, not exported from the package index. Throws a
 * plain `Error` on malformed input; the extractor wraps it in `MtlsError`.
 */

/**
 * Decode a single PEM block to its DER bytes; whitespace in the base64 body
 * is stripped. Input must already be URL-decoded (the header parsers do it).
 */
export const pemToDer = (pem: string): Uint8Array => {
	// Strip leading/trailing whitespace to be tolerant of copy-paste noise.
	const trimmed = pem.trim();

	// Locate the required BEGIN/END markers — RFC 7468 §2.
	const beginMatch = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(trimmed);
	const endMatch = /-----END ([A-Z0-9 ]+)-----/.exec(trimmed);

	if (!beginMatch || !endMatch) {
		throw new Error("PEM block is missing BEGIN or END marker");
	}

	// Verify marker type consistency — a stray BEGIN PRIVATE KEY / END CERTIFICATE
	// pair would silently corrupt the DER if we didn't check.
	if (beginMatch[1] !== endMatch[1]) {
		throw new Error(`PEM BEGIN/END type mismatch: BEGIN ${beginMatch[1]} vs END ${endMatch[1]}`);
	}

	// Extract the base64 body between markers, stripping all whitespace.
	// We use the indexes from the regex rather than a multi-step split so
	// embedded whitespace (including CRLF) doesn't silently produce an empty body.
	const bodyStart = beginMatch.index + beginMatch[0].length;
	const bodyEnd = endMatch.index;
	const base64Body = trimmed.slice(bodyStart, bodyEnd).replace(/\s/g, "");

	if (base64Body.length === 0) {
		throw new Error("PEM block has empty base64 body");
	}

	// Validate that the body contains only valid base64 characters.
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64Body)) {
		throw new Error("PEM base64 body contains invalid characters");
	}

	return new Uint8Array(Buffer.from(base64Body, "base64"));
};

/**
 * Encode DER bytes to PEM with 64-character lines. `type` is the marker label
 * (RFC 7468 §13).
 */
export const derToPem = (der: Uint8Array, type = "CERTIFICATE"): string => {
	const base64 = Buffer.from(der).toString("base64");

	// RFC 7468 §2 mandates 64-character line length for interoperability.
	const lines: string[] = [];
	for (let i = 0; i < base64.length; i += 64) {
		lines.push(base64.slice(i, i + 64));
	}

	return [`-----BEGIN ${type}-----`, ...lines, `-----END ${type}-----`].join("\n");
};
