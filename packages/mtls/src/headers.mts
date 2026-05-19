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
 * Header dialect parsers for extracting client certificate PEM from reverse-
 * proxy forwarded-cert headers.
 *
 * Two dialects ship in Phase 3 Stage 1 per spec §1.3:
 *   - `"envoy"`: Envoy XFCC (x-forwarded-client-cert) header format.
 *   - `"plain-pem"`: Raw PEM value, possibly URL-encoded.
 *
 * Both parsers are internal — NOT re-exported from index.mts. Consumers
 * select a dialect via the `certHeaderDialect` config key; `createMtlsMechanism`
 * dispatches to the correct parser at extraction time.
 *
 * Per Wave 2 Phase 3 spec §5.4 (CertHeaderDialect) + §6.2 (step 2 — dialect parse).
 */

/**
 * The set of supported certificate header dialect identifiers.
 *
 * Exported from index.mts per spec §5.1 so operators can reference the type
 * when building typed config objects. The union is closed at Stage 1 — a
 * future nginx dialect adds a new arm via a semver-minor bump, not a
 * catch-all `string`.
 *
 * Per Wave 2 Phase 3 spec §5.4.
 */
export type CertHeaderDialect = "envoy" | "plain-pem";

/**
 * Maximum permitted raw header value size in bytes (UTF-16 code units, which
 * for ASCII PEM bodies is 1:1 with bytes). Defense-in-depth against DoS via
 * oversize XFCC headers from a misbehaving or malicious upstream (Codex review
 * Round 1 Important #1, PR for Sub-PR 3a).
 *
 * Realistic XFCC values are well under 10KB for a single cert + chain (≈3KB
 * per typical RSA-2048 cert). 16KB caps the upper realistic envelope plus
 * headroom for URL-percent-encoding bloat (≤3× expansion).
 *
 * A value exceeding this cap → `Error("header value exceeds size cap")`, which
 * the extractor wraps as `MtlsError("malformed_header", …)`.
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

/**
 * Detect whether a string contains URL-percent-encoded characters.
 *
 * Used internally to decide whether to URL-decode before further processing.
 * A string that contains neither `%20` nor `%0A` (and no `%` at all) is
 * treated as literal.
 */
const isUrlEncoded = (value: string): boolean => /%[0-9A-Fa-f]{2}/.test(value);

/**
 * URL-decode a percent-encoded value, normalizing `decodeURIComponent`'s
 * native `URIError` into a plain `Error` so the dialect parsers never leak
 * a `URIError` to the call site. The extractor (Sub-PR 3b) wraps all
 * primitive errors as `MtlsError("malformed_header", …)` — without this
 * wrapper, a `URIError` would surface as the wrong reason code (Codex
 * review Round 1 Important #3).
 */
const safeDecodeURIComponent = (value: string, field: string): string => {
	try {
		return decodeURIComponent(value);
	} catch {
		throw new Error(`invalid percent-encoding in ${field}`);
	}
};

/**
 * Strip enclosing double-quotes from an XFCC field value per Envoy's
 * documented format. Envoy 1.18+ emits quoted values for fields whose
 * payload contains structural characters (`Cert="…"`, `Chain="…"`).
 * Backslash-escapes within quotes are handled per RFC 7230 quoted-string
 * grammar (the common cases are `\"` and `\\`).
 *
 * Non-quoted values are returned verbatim. Mismatched leading-only or
 * trailing-only quote raises a parse error to surface the malformed
 * dialect to operators rather than silently passing through (Codex review
 * Round 1 Important #2 / Claude Minor #2 convergence).
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
 * Phase 3 Stage 1 processes only the FIRST element (the client-facing hop).
 * Required field: `Cert=<url-encoded-pem>`. Optional field: `Chain=<url-encoded-pem>`.
 * `By=` and `Hash=` are parsed-past but not used — they are informational.
 *
 * Parse failure → throws a plain `Error`. The call site (extractor.mts step 2)
 * wraps it into `MtlsError("malformed_header", "envoy XFCC parse failure: <detail>")`.
 *
 * Per Wave 2 Phase 3 spec §6.2.
 */
export const parseEnvoyXfccHeader = (value: string): ParsedCertHeader => {
	// Defense-in-depth size cap before any string ops (Codex Round 1 Important #1).
	if (value.length > MAX_RAW_HEADER_BYTES) {
		throw new Error(
			`XFCC header value exceeds size cap (${value.length} > ${MAX_RAW_HEADER_BYTES} bytes)`,
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

	// Cert= and Chain= values are URL-percent-encoded per the XFCC spec.
	// Envoy 1.18+ may also wrap structural-character values in quoted-strings —
	// unquoteXfccField handles `Cert="..."` and the standard `\"`/`\\` escapes.
	const certPem = safeDecodeURIComponent(unquoteXfccField(rawCert, "Cert"), "Cert");
	if (certPem.length > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`XFCC Cert= decoded payload exceeds size cap (${certPem.length} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}

	const rawChain = fields.get("Chain");
	const chainPem =
		rawChain !== undefined
			? safeDecodeURIComponent(unquoteXfccField(rawChain, "Chain"), "Chain")
			: undefined;
	if (chainPem !== undefined && chainPem.length > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`XFCC Chain= decoded payload exceeds size cap (${chainPem.length} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}

	return { certPem, ...(chainPem !== undefined ? { chainPem } : {}) };
};

/**
 * Parse a plain-PEM certificate header.
 *
 * The header value is either a literal PEM block or a URL-percent-encoded
 * PEM block. URL-encoded values are decoded automatically.
 *
 * **Multi-PEM concatenation is rejected** (spec OQ1 §14.1 strict decision):
 * a header value containing multiple `-----BEGIN CERTIFICATE-----` blocks is
 * malformed_header. Operators who need to convey a chain MUST use the `envoy`
 * dialect with its `Chain=` field instead.
 *
 * Parse failure → throws a plain `Error`. The call site wraps it into
 * `MtlsError("malformed_header", …)`.
 *
 * Per Wave 2 Phase 3 spec §6.2 + OQ1 §14.1.
 */
export const parsePlainPemHeader = (value: string): ParsedCertHeader => {
	if (!value || value.trim().length === 0) {
		throw new Error("plain-pem header value is empty");
	}

	// Defense-in-depth size cap (Codex Round 1 Important #1).
	if (value.length > MAX_RAW_HEADER_BYTES) {
		throw new Error(
			`plain-pem header value exceeds size cap (${value.length} > ${MAX_RAW_HEADER_BYTES} bytes)`,
		);
	}

	// URL-decode if the value contains percent-encoded sequences.
	// This handles the common case of an HTTP header that was URL-encoded
	// by the reverse proxy (e.g. nginx `$ssl_client_escaped_cert`).
	// safeDecodeURIComponent normalizes URIError → plain Error so the
	// extractor wraps it consistently (Codex Round 1 Important #3).
	const decoded = isUrlEncoded(value) ? safeDecodeURIComponent(value, "plain-pem value") : value;
	if (decoded.length > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`plain-pem decoded payload exceeds size cap (${decoded.length} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}

	// OQ1 strict: reject multi-PEM concatenations. A legitimate single cert
	// has exactly one BEGIN marker; two or more indicates a chain was passed
	// where only a leaf cert is expected. Reject rather than silently use the
	// first cert (downgrade-prevention, per spec §3.3).
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
