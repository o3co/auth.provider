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
 * Parsers that extract the client certificate PEM from a reverse proxy's
 * forwarded-cert header, in two dialects: `"envoy"` (Envoy XFCC) and
 * `"plain-pem"` (a PEM value, possibly URL-encoded). Internal, not
 * re-exported from index.mts: `createMtlsMechanism` picks one by
 * `certHeaderDialect`.
 */

/**
 * The supported certificate header dialects. A closed union: a new dialect
 * is a new arm, not a catch-all `string`.
 */
export type CertHeaderDialect = "envoy" | "plain-pem";

/**
 * Maximum raw header value size in UTF-8 bytes, against DoS via an oversize
 * header from a misbehaving or malicious upstream. Measured in UTF-8 bytes,
 * not `value.length`, so multi-byte characters cannot slip past it.
 * Realistic XFCC values are well under 10KB for a cert and its chain (about
 * 3KB per RSA-2048 cert); 16KB adds headroom for percent-encoding.
 */
const MAX_RAW_HEADER_BYTES = 16 * 1024;

/**
 * Maximum permitted decoded PEM payload size in bytes. URL-decode can expand
 * up to ~3× from `%XX` sequences; the raw-cap above bounds the input, this
 * cap bounds the working set after decode.
 */
const MAX_DECODED_PAYLOAD_BYTES = 64 * 1024;

/** Structured output from both dialect parsers. */
interface ParsedCertHeader {
	/** PEM-encoded leaf certificate (already URL-decoded if applicable). */
	readonly certPem: string;
	/** PEM-encoded intermediate chain (XFCC `Chain=` value). Absent in plain-PEM dialect. */
	readonly chainPem?: string;
}

/** Whether a string contains a `%XX` escape; without one it is taken literally. */
const isUrlEncoded = (value: string): boolean => /%[0-9A-Fa-f]{2}/.test(value);

/**
 * `decodeURIComponent`, with its `URIError` normalized to a plain `Error` so
 * the dialect parsers throw one kind of error for malformed input.
 */
const safeDecodeURIComponent = (value: string, field: string): string => {
	try {
		return decodeURIComponent(value);
	} catch {
		throw new Error(`invalid percent-encoding in ${field}`);
	}
};

/**
 * Strip enclosing double-quotes from an XFCC field value: Envoy 1.18+ quotes
 * values containing structural characters (`Cert="…"`). Escapes are undone
 * per the RFC 7230 quoted-string grammar (`\"`, `\\`). Unquoted values pass
 * through; a quote at only one end is a parse error, not passed through.
 */
const unquoteXfccField = (raw: string, fieldName: string): string => {
	if (raw.length === 0) return raw;
	const leading = raw.startsWith('"');
	const trailing = raw.endsWith('"');
	if (!leading && !trailing) return raw;
	if (leading !== trailing || raw.length < 2) {
		throw new Error(`XFCC field "${fieldName}" has mismatched quoting`);
	}
	// Strip enclosing quotes + un-escape \" and \\ per quoted-string grammar.
	return raw.slice(1, -1).replace(/\\(["\\])/g, "$1");
};

/**
 * Parse an Envoy XFCC (x-forwarded-client-cert) header value.
 *
 * XFCC grammar (simplified from Envoy docs):
 *   XFCC = element *("," element)
 *   element = field *(";" field)
 *   field = token "=" value
 *
 * Only the first element (the client-facing hop) is read. `Cert=` is
 * required, `Chain=` optional (both URL-encoded PEM); other fields are
 * ignored. Throws a plain `Error` on malformed input.
 */
export const parseEnvoyXfccHeader = (value: string): ParsedCertHeader => {
	// Size cap before any string work.
	const rawByteLen = Buffer.byteLength(value, "utf8");
	if (rawByteLen > MAX_RAW_HEADER_BYTES) {
		throw new Error(
			`XFCC header value exceeds size cap (${rawByteLen} > ${MAX_RAW_HEADER_BYTES} bytes)`,
		);
	}

	// Use only the first XFCC element — Envoy prepends the client-facing hop at
	// the front of the comma-separated list when chaining proxies.
	const firstElement = value.split(",")[0]?.trim();
	if (!firstElement) {
		throw new Error("XFCC header is empty");
	}

	// Parse semicolon-delimited key=value fields.
	// NOTE: PEM values themselves can contain "=", "+" etc., so we split on the
	// FIRST "=" only within each semicolon-delimited field.
	const fields = new Map<string, string>();
	for (const field of firstElement.split(";")) {
		const eqIdx = field.indexOf("=");
		if (eqIdx === -1) {
			// Field with no value (e.g. a standalone token) — skip silently.
			continue;
		}
		const key = field.slice(0, eqIdx).trim();
		const rawValue = field.slice(eqIdx + 1).trim();
		if (key.length > 0) {
			fields.set(key, rawValue);
		}
	}

	const rawCert = fields.get("Cert");
	if (!rawCert) {
		throw new Error('XFCC header is missing required "Cert=" field');
	}

	// Cert= and Chain= are URL-encoded, and may be quoted (unquoteXfccField).
	const certPem = safeDecodeURIComponent(unquoteXfccField(rawCert, "Cert"), "Cert");
	const certByteLen = Buffer.byteLength(certPem, "utf8");
	if (certByteLen > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`XFCC Cert= decoded payload exceeds size cap (${certByteLen} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}

	const rawChain = fields.get("Chain");
	const chainPem =
		rawChain !== undefined
			? safeDecodeURIComponent(unquoteXfccField(rawChain, "Chain"), "Chain")
			: undefined;
	if (chainPem !== undefined) {
		const chainByteLen = Buffer.byteLength(chainPem, "utf8");
		if (chainByteLen > MAX_DECODED_PAYLOAD_BYTES) {
			throw new Error(
				`XFCC Chain= decoded payload exceeds size cap (${chainByteLen} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
			);
		}
	}

	return { certPem, ...(chainPem !== undefined ? { chainPem } : {}) };
};

/**
 * Parse a plain-PEM certificate header: one PEM block, literal or
 * URL-encoded. More than one block is rejected; a chain needs the `envoy`
 * dialect's `Chain=`. Throws a plain `Error` on malformed input.
 */
export const parsePlainPemHeader = (value: string): ParsedCertHeader => {
	// Size cap before any trim or decode.
	const rawByteLen = Buffer.byteLength(value, "utf8");
	if (rawByteLen > MAX_RAW_HEADER_BYTES) {
		throw new Error(
			`plain-pem header value exceeds size cap (${rawByteLen} > ${MAX_RAW_HEADER_BYTES} bytes)`,
		);
	}

	if (!value || value.trim().length === 0) {
		throw new Error("plain-pem header value is empty");
	}

	// A proxy may URL-encode the value (e.g. nginx `$ssl_client_escaped_cert`).
	const decoded = isUrlEncoded(value) ? safeDecodeURIComponent(value, "plain-pem value") : value;
	const decodedByteLen = Buffer.byteLength(decoded, "utf8");
	if (decodedByteLen > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`plain-pem decoded payload exceeds size cap (${decodedByteLen} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}

	// Two or more BEGIN markers mean a chain where only a leaf is expected:
	// rejected rather than silently using the first cert (downgrade prevention).
	const beginCount = (decoded.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
	if (beginCount === 0) {
		throw new Error("plain-pem header does not contain a PEM certificate block");
	}
	if (beginCount > 1) {
		throw new Error(
			"plain-pem header contains multiple PEM blocks; use the envoy dialect for chain transport",
		);
	}

	return { certPem: decoded };
};
