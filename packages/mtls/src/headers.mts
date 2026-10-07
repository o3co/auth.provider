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
 * `certHeaderDialect`. Each yields one leaf certificate or throws: a header
 * that could be read as naming two (a repeated XFCC key, a second PEM block,
 * an XFCC `Hash=` of another certificate) is refused.
 */

import { createHash } from "node:crypto";
import { pemToDer } from "./pem.mjs";

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

/** Every PEM BEGIN marker, whatever its label. */
const PEM_BEGIN_MARKER = /-----BEGIN ([A-Z0-9 ]+)-----/g;

/**
 * The labels of the PEM blocks in a decoded value, in order. `pemToDer` reads
 * the first block of any label, so a value is one certificate only when this
 * is exactly `["CERTIFICATE"]`.
 */
const pemBlockLabels = (pem: string): readonly string[] =>
	Array.from(pem.matchAll(PEM_BEGIN_MARKER), (match) => match[1] ?? "");

/**
 * The XFCC keys Envoy writes once per element. A second occurrence makes the
 * element ambiguous, and the header is refused. Envoy repeats `By`, `URI`
 * and `DNS`, one field per Subject Alternative Name (`By` for the proxy's own
 * certificate, `URI` and `DNS` for the client's); this package does not read
 * them, so their repetition is accepted. Every other key is ignored.
 */
const XFCC_SINGLE_KEYS = ["Hash", "Cert", "Chain", "Subject"] as const;
type XfccSingleKey = (typeof XFCC_SINGLE_KEYS)[number];

const isXfccSingleKey = (key: string): key is XfccSingleKey =>
	(XFCC_SINGLE_KEYS as readonly string[]).includes(key);

/**
 * Read the fields of the first XFCC element, quoting undone.
 *
 * XFCC grammar (Envoy):
 *   XFCC    = element *("," element)
 *   element = field *(";" field)
 *   field   = key "=" value
 *   value   = token / quoted-string
 *
 * `,` ends the element and `;` ends a field only outside a double-quoted
 * string. Inside one, `\` takes the next character literally (RFC 7230
 * quoted-string), so a quoted Subject, URI or DNS value may hold `,`, `;`
 * and `=`. A quote that is not the whole value (opened mid-value, never
 * closed, or followed by more text) is refused. A field with no `=` is
 * skipped. Returns the fields in order, repeated keys included.
 */
const readFirstXfccElement = (value: string): ReadonlyArray<readonly [string, string]> => {
	const fields: Array<readonly [string, string]> = [];
	let key = "";
	let fieldValue = "";
	// "key" until the first "=", then the value: "start" (only whitespace so
	// far), "bare" (a token), "quoted" (inside a quoted-string) or "closed"
	// (after its closing quote).
	let state: "key" | "start" | "bare" | "quoted" | "closed" = "key";

	const endField = (): void => {
		// A token's trailing whitespace is not part of it; a quoted value's is.
		if (state !== "key")
			fields.push([key.trim(), state === "bare" ? fieldValue.trimEnd() : fieldValue]);
		key = "";
		fieldValue = "";
		state = "key";
	};

	for (let i = 0; i < value.length; i++) {
		const ch = value.charAt(i);
		if (state === "quoted") {
			if (ch === "\\") {
				i++;
				if (i >= value.length) break;
				fieldValue += value.charAt(i);
			} else if (ch === '"') {
				state = "closed";
			} else {
				fieldValue += ch;
			}
			continue;
		}
		if (ch === "," || ch === ";") {
			endField();
			if (ch === ",") return fields;
			continue;
		}
		switch (state) {
			case "key":
				if (ch === '"') throw new Error("XFCC field name has mismatched quoting");
				if (ch === "=") state = "start";
				else key += ch;
				break;
			case "start":
				if (ch === '"') state = "quoted";
				else if (ch.trim().length > 0) {
					fieldValue += ch;
					state = "bare";
				}
				break;
			case "bare":
				if (ch === '"') {
					throw new Error(`XFCC field "${key.trim()}" has mismatched quoting`);
				}
				fieldValue += ch;
				break;
			case "closed":
				if (ch.trim().length > 0) {
					throw new Error(`XFCC field "${key.trim()}" has mismatched quoting`);
				}
				break;
		}
	}
	if (state === "quoted") {
		throw new Error(`XFCC field "${key.trim()}" has mismatched quoting`);
	}
	endField();
	return fields;
};

/**
 * Parse an Envoy XFCC (x-forwarded-client-cert) header value.
 *
 * Only the first element (the client-facing hop) is read, by the grammar in
 * {@link readFirstXfccElement}. `Cert=` is required and `Chain=` optional
 * (both URL-encoded PEM). `Hash=`, when present, must be the hex SHA-256 of
 * the `Cert=` DER, compared case-insensitively. `Hash`, `Cert`, `Chain` and
 * `Subject` may appear once; `By`, `URI` and `DNS` may repeat; any other key
 * is ignored. Throws a plain `Error` on malformed input.
 */
export const parseEnvoyXfccHeader = (value: string): ParsedCertHeader => {
	// Size cap before any string work.
	const rawByteLen = Buffer.byteLength(value, "utf8");
	if (rawByteLen > MAX_RAW_HEADER_BYTES) {
		throw new Error(
			`XFCC header value exceeds size cap (${rawByteLen} > ${MAX_RAW_HEADER_BYTES} bytes)`,
		);
	}

	// Envoy prepends the client-facing hop at the front of the comma-separated
	// list when chaining proxies.
	const elementFields = readFirstXfccElement(value);
	if (elementFields.length === 0) {
		throw new Error("XFCC header is empty");
	}

	const fields = new Map<XfccSingleKey, string>();
	for (const [key, fieldValue] of elementFields) {
		// `By`, `URI`, `DNS` and unknown keys are not read.
		if (!isXfccSingleKey(key)) continue;
		if (fields.has(key)) {
			throw new Error(`XFCC field "${key}" appears more than once in the element`);
		}
		fields.set(key, fieldValue);
	}

	const rawCert = fields.get("Cert");
	if (!rawCert) {
		throw new Error('XFCC header is missing required "Cert=" field');
	}

	const certPem = safeDecodeURIComponent(rawCert, "Cert");
	const certByteLen = Buffer.byteLength(certPem, "utf8");
	if (certByteLen > MAX_DECODED_PAYLOAD_BYTES) {
		throw new Error(
			`XFCC Cert= decoded payload exceeds size cap (${certByteLen} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
		);
	}
	// One leaf: a second block of any label is refused rather than letting
	// `pemToDer` pick the first.
	if (pemBlockLabels(certPem).length > 1) {
		throw new Error("XFCC Cert= contains multiple PEM blocks; the chain belongs in Chain=");
	}

	const rawChain = fields.get("Chain");
	const chainPem = rawChain !== undefined ? safeDecodeURIComponent(rawChain, "Chain") : undefined;
	if (chainPem !== undefined) {
		const chainByteLen = Buffer.byteLength(chainPem, "utf8");
		if (chainByteLen > MAX_DECODED_PAYLOAD_BYTES) {
			throw new Error(
				`XFCC Chain= decoded payload exceeds size cap (${chainByteLen} > ${MAX_DECODED_PAYLOAD_BYTES} bytes)`,
			);
		}
	}

	const hash = fields.get("Hash");
	if (hash !== undefined) {
		let der: Uint8Array;
		try {
			der = pemToDer(certPem);
		} catch (err) {
			throw new Error("XFCC Hash= cannot be checked: Cert= is not a decodable PEM block", {
				cause: err,
			});
		}
		const expected = createHash("sha256").update(der).digest("hex");
		if (hash.toLowerCase() !== expected) {
			throw new Error("XFCC Hash= is not the SHA-256 of the Cert= certificate");
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

	// Two or more BEGIN markers, of any label, mean more than the one leaf
	// expected: rejected rather than letting `pemToDer` read the first block.
	const labels = pemBlockLabels(decoded);
	if (labels.length > 1) {
		throw new Error(
			"plain-pem header contains multiple PEM blocks; use the envoy dialect for chain transport",
		);
	}
	if (labels[0] !== "CERTIFICATE") {
		throw new Error("plain-pem header does not contain a PEM certificate block");
	}

	return { certPem: decoded };
};
