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
	const certPem = decodeURIComponent(rawCert);

	const rawChain = fields.get("Chain");
	const chainPem = rawChain !== undefined ? decodeURIComponent(rawChain) : undefined;

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

	// URL-decode if the value contains percent-encoded sequences.
	// This handles the common case of an HTTP header that was URL-encoded
	// by the reverse proxy (e.g. nginx `$ssl_client_escaped_cert`).
	const decoded = isUrlEncoded(value) ? decodeURIComponent(value) : value;

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
