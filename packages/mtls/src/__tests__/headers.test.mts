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
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseEnvoyXfccHeader, parsePlainPemHeader } from "#/headers.mjs";

/**
 * Test fixture: fixed self-signed P-256 cert (same as used in other tests).
 * Used verbatim and in URL-encoded form to test both header dialects.
 */
const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUaBppoI8WPFk51saIFsb3ITafYDMwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjA1MTkwMzM5MDdaFw0yNzA1MTkwMzM5MDda
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT/xsy0
D008eq7Qp+cyWHxqcThSc9YFSl9v/FGE9s9HqbMY5ku00iXUW2R/Nu18PN1y6Osa
MdfFxFOqPFLl180po1MwUTAdBgNVHQ4EFgQUQey1RDkeBYfD/xuliPfC0Qv0WEow
HwYDVR0jBBgwFoAUQey1RDkeBYfD/xuliPfC0Qv0WEowDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAzIC0cVYrlH7qLZ2r0OqYXFci9/EveGi0yhGi
hXs25+0CIQDITvqroFES8r+bSdPCJGaQMVxps8L823m1axWCE+eUvA==
-----END CERTIFICATE-----`;

/** Second PEM block used to simulate a chain or multi-cert scenarios. */
const TEST_CHAIN_PEM = `-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUaBppoI8WPFk51saIFsb3ITafYDMwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjA1MTkwMzM5MDdaFw0yNzA1MTkwMzM5MDda
MA8xDTALBgNVBAMMBHRlc3QAAAA=
-----END CERTIFICATE-----`;

const ENCODED_CERT = encodeURIComponent(TEST_CERT_PEM);
const ENCODED_CHAIN = encodeURIComponent(TEST_CHAIN_PEM);

/** Lowercase hex SHA-256 of a certificate's DER: what Envoy writes as `Hash=`. */
const sha256Hex = (pem: string): string =>
	createHash("sha256").update(new X509Certificate(pem).raw).digest("hex");

const TEST_CERT_HASH = sha256Hex(TEST_CERT_PEM);

describe("parseEnvoyXfccHeader", () => {
	it("parses a well-formed XFCC header with Cert= only", () => {
		const xfcc = `By=spiffe://cluster.local/ns/default/sa/server;Hash=${TEST_CERT_HASH};Cert=${ENCODED_CERT}`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
		expect(result.chainPem).toBeUndefined();
	});

	it("parses a well-formed XFCC header with both Cert= and Chain=", () => {
		const xfcc = `By=spiffe://cluster.local;Hash=${TEST_CERT_HASH};Cert=${ENCODED_CERT};Chain=${ENCODED_CHAIN}`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
		expect(result.chainPem).toBe(TEST_CHAIN_PEM);
	});

	it("throws when Cert= field is missing from the XFCC header", () => {
		const xfcc = `By=spiffe://cluster.local;Hash=abc123`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Cert=");
	});

	it("uses only the first XFCC element when multiple comma-separated elements are present", () => {
		// Envoy prepends the client-facing hop first — subsequent elements are
		// from inner hops and MUST NOT be used for binding.
		const xfcc = `Hash=${TEST_CERT_HASH};Cert=${ENCODED_CERT},Cert=otherstuff`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
	});

	it("URL-decodes the Cert= value correctly (roundtrip)", () => {
		const xfcc = `Hash=${TEST_CERT_HASH};Cert=${ENCODED_CERT}`;
		const result = parseEnvoyXfccHeader(xfcc);
		// After URL-decoding, the PEM must match the original exactly.
		expect(result.certPem).toContain("-----BEGIN CERTIFICATE-----");
		expect(result.certPem).toContain("-----END CERTIFICATE-----");
	});

	it("strips enclosing double-quotes from Cert= value (Envoy 1.18+ quoted-string form)", () => {
		// Envoy may quote field values whose payloads contain structural
		// characters.
		const xfcc = `By="spiffe://cluster.local/sa/server";Hash=${TEST_CERT_HASH};Cert="${ENCODED_CERT}"`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
	});

	it("rejects mismatched leading-only quote on Cert= field", () => {
		const xfcc = `Cert="${ENCODED_CERT}`; // missing trailing quote
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("mismatched quoting");
	});

	it("rejects an XFCC header that exceeds the raw size cap", () => {
		// Defense-in-depth size cap.
		const oversize = `Cert=${"x".repeat(20 * 1024)}`;
		expect(() => parseEnvoyXfccHeader(oversize)).toThrow("size cap");
	});

	it("measures the raw size cap in UTF-8 bytes, not UTF-16 code units (multi-byte cannot bypass)", () => {
		// An attacker who emits non-ASCII
		// characters could bypass a cap measured in `value.length` (UTF-16 code
		// units) because multi-byte UTF-8 chars take fewer code units than bytes.
		// Each "あ" is 1 UTF-16 code unit but 3 UTF-8 bytes; 6KB code units = 18KB
		// UTF-8 bytes, which exceeds the 16KB raw cap.
		const multibyte = `Cert=${"あ".repeat(6 * 1024)}`;
		expect(() => parseEnvoyXfccHeader(multibyte)).toThrow("size cap");
	});

	it("normalizes invalid percent-encoding into a plain Error (not URIError)", () => {
		// The safeDecodeURIComponent wrapper.
		// `%C3` is a partial UTF-8 multi-byte sequence — looks URL-encoded
		// (matches the isUrlEncoded regex), but decodeURIComponent throws
		// URIError mid-decode. The wrapper MUST rethrow as a plain Error.
		const xfcc = "Cert=%C3-truncated";
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("invalid percent-encoding");
		// MUST be a plain Error, never a URIError — verify by class name.
		try {
			parseEnvoyXfccHeader(xfcc);
		} catch (err) {
			expect(err).toBeInstanceOf(Error);
			expect((err as Error).constructor.name).toBe("Error");
		}
	});
});

/** Two distinct real certificates, so a test can tell which one the parser returned. */
const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");
const OTHER_PEM = readFileSync(join(fixturesDir, "root.pem"), "utf8");
const INTERMEDIATE_PEM = readFileSync(join(fixturesDir, "intermediate.pem"), "utf8");
const LEAF = encodeURIComponent(LEAF_PEM);
const OTHER = encodeURIComponent(OTHER_PEM);
const INTERMEDIATE = encodeURIComponent(INTERMEDIATE_PEM);
const LEAF_HASH = sha256Hex(LEAF_PEM);

describe("parseEnvoyXfccHeader — XFCC grammar", () => {
	it("refuses an element in which Cert= appears twice", () => {
		const xfcc = `Cert=${LEAF};Cert=${OTHER}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("more than once");
	});

	it.each(["Hash", "Chain", "Subject"])("refuses an element in which %s= appears twice", (key) => {
		const value = key === "Hash" ? LEAF_HASH : key === "Chain" ? INTERMEDIATE : '"CN=a"';
		const xfcc = `Cert=${LEAF};${key}=${value};${key}=${value}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("more than once");
	});

	it.each([
		["URI", `URI="spiffe://example/ns/a;Cert=${OTHER};x=y"`],
		["DNS", `DNS="client.example.com;Cert=${OTHER};x=y"`],
		["Subject", `Subject="CN=client;Cert=${OTHER};O=Example"`],
	])("keeps ;Cert= inside a quoted %s value part of that value", (_key, field) => {
		const xfcc = `By=spiffe://example/ns/proxy;Hash=${LEAF_HASH};Cert="${LEAF}";${field}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("keeps ;Cert= inside a quoted value that precedes Cert= part of that value", () => {
		const xfcc = `Subject="CN=client;Cert=${OTHER};O=Example";Hash=${LEAF_HASH};Cert="${LEAF}"`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("reads an RFC 2253 Subject whose \\; escape precedes Cert= as one value", () => {
		const subject = `CN=client\\;Cert=${OTHER}\\;x=y,O=Example\\, Inc.,C=US`;
		const xfcc = `Hash=${LEAF_HASH};Cert="${LEAF}";Subject="${subject}"`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("refuses an unquoted Subject whose \\;Cert= becomes a second Cert= field", () => {
		const xfcc = `Cert=${LEAF};Subject=CN=client\\;Cert=${OTHER}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("more than once");
	});

	it("honours a backslash-escaped double quote inside a quoted value", () => {
		const xfcc = `Subject="CN=a \\"quoted\\";Cert=${OTHER}";Hash=${LEAF_HASH};Cert=${LEAF}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("does not end the first element at a comma inside a quoted value", () => {
		const xfcc = `By=spiffe://example/ns/proxy;Subject="CN=client,O=Example,C=US";Hash=${LEAF_HASH};Cert="${LEAF}"`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("ends the first element at the first comma outside quotes", () => {
		const xfcc = `Subject="CN=a,O=b";Hash=${LEAF_HASH};Cert=${LEAF},Cert=${OTHER}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("refuses a quoted value that never closes", () => {
		const xfcc = `Subject="CN=a;Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("mismatched quoting");
	});

	it("refuses text after a closing quote", () => {
		const xfcc = `Cert="${LEAF}"trailing`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("mismatched quoting");
	});

	it("ignores keys it does not read, even when they repeat", () => {
		const xfcc = `Foo=1;Foo=2;Certificate=${OTHER};Hash=${LEAF_HASH};Cert=${LEAF}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("matches keys case-insensitively", () => {
		const xfcc = `by=spiffe://example;HASH=${LEAF_HASH};cErT=${LEAF};chain=${INTERMEDIATE};SUBJECT="CN=a";uri=spiffe://example/ns/a;dns=a.example.com`;
		const parsed = parseEnvoyXfccHeader(xfcc);
		expect(parsed.certPem).toBe(LEAF_PEM);
		expect(parsed.chainPem).toBe(INTERMEDIATE_PEM);
	});

	it.each([
		["Cert", "cErT", LEAF, OTHER],
		["Hash", "hash", LEAF_HASH, LEAF_HASH],
		["Chain", "CHAIN", INTERMEDIATE, INTERMEDIATE],
		["Subject", "subject", '"CN=a"', '"CN=a"'],
	])("refuses %s= repeated as %s=", (key, otherCase, first, second) => {
		const cert = key === "Cert" ? "" : `Cert=${LEAF};`;
		const xfcc = `${cert}${key}=${first};${otherCase}=${second}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("more than once");
	});

	it("accepts By, URI and DNS repeated in mixed case", () => {
		const xfcc = `By=a;by=b;URI=c;uri=d;DNS=e;dns=f;Hash=${LEAF_HASH};Cert=${LEAF}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("refuses a Cert= value that holds more than one PEM block", () => {
		const xfcc = `Cert=${encodeURIComponent(`${LEAF_PEM}\n${OTHER_PEM}`)}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("multiple PEM blocks");
	});

	it("refuses a Cert= value whose one PEM block is not labelled CERTIFICATE", () => {
		const relabelled = LEAF_PEM.replaceAll("CERTIFICATE", "X509 CERTIFICATE");
		const xfcc = `Hash=${LEAF_HASH};Cert=${encodeURIComponent(relabelled)}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("PEM certificate block");
	});

	it("refuses a Cert= value whose first PEM block carries another label", () => {
		const relabelled = OTHER_PEM.replaceAll("CERTIFICATE", "X509 CERTIFICATE");
		const xfcc = `Cert=${encodeURIComponent(`${relabelled}\n${LEAF_PEM}`)}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("multiple PEM blocks");
	});
});

describe("parseEnvoyXfccHeader — Hash=", () => {
	it("accepts a Hash= equal to the SHA-256 of the Cert= DER", () => {
		const xfcc = `Hash=${LEAF_HASH};Cert=${LEAF}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("compares Hash= case-insensitively", () => {
		const xfcc = `Hash=${LEAF_HASH.toUpperCase()};Cert=${LEAF}`;
		expect(parseEnvoyXfccHeader(xfcc).certPem).toBe(LEAF_PEM);
	});

	it("refuses a Hash= that is the SHA-256 of another certificate", () => {
		const xfcc = `Hash=${sha256Hex(OTHER_PEM)};Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it("refuses a Hash= that is not a SHA-256 hex digest", () => {
		const xfcc = `Hash=abc123;Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it("refuses a Hash= when Cert= is not a decodable PEM block", () => {
		const xfcc = `Hash=${LEAF_HASH};Cert=${encodeURIComponent("-----BEGIN CERTIFICATE-----\nA*B\n-----END CERTIFICATE-----")}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it.each(["hash", "HASH", "hAsH"])("checks a %s= that is not the SHA-256 of Cert=", (key) => {
		const xfcc = `${key}=${"0".repeat(64)};Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it("checks a lowercase hash= against a lowercase cert=", () => {
		const xfcc = `hash=${sha256Hex(OTHER_PEM)};cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it("refuses an element without Hash=", () => {
		expect(() => parseEnvoyXfccHeader(`Cert=${LEAF}`)).toThrow("Hash=");
	});

	it("refuses an element whose Hash= names another certificate than its Cert=, though a later element holds that one", () => {
		const xfcc = `Hash=${LEAF_HASH};URI=x;Cert=${OTHER},URI=y;Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});

	it("refuses an element without Hash= whose unquoted value ends it early at a comma", () => {
		// The proxy wrote `URI=x,Cert=<other>` as one unquoted value before its
		// own `Cert=`: the comma ends the first element after `Cert=<other>`.
		const xfcc = `By=spiffe://example/ns/proxy;URI=x;Cert=${OTHER},URI=y;Cert=${LEAF}`;
		expect(() => parseEnvoyXfccHeader(xfcc)).toThrow("Hash=");
	});
});

/**
 * Header shapes as Envoy writes them (`forward_client_cert_details:
 * SANITIZE_SET` with every `set_current_client_cert_details` field on): each
 * must give the same certificate it gave before the grammar-aware reader.
 */
describe("parseEnvoyXfccHeader — Envoy-shaped headers", () => {
	it.each([
		[
			"every field, Cert and Chain quoted",
			`By=spiffe://cluster.local/ns/default/sa/server;Hash=${LEAF_HASH};Cert="${LEAF}";Chain="${INTERMEDIATE}";Subject="CN=client,O=Example,C=US";URI=spiffe://cluster.local/ns/default/sa/client;DNS=client.example.com`,
		],
		[
			"every field unquoted except Subject",
			`By=spiffe://cluster.local/ns/default/sa/server;Hash=${LEAF_HASH};Cert=${LEAF};Chain=${INTERMEDIATE};Subject="/C=US/ST=CA/L=San Francisco/OU=Example/CN=Test Client";URI=http://testclient.example.com`,
		],
		[
			"a certificate with several DNS and URI SANs",
			`By=http://frontend.example.com;Hash=${LEAF_HASH};Cert="${LEAF}";Subject="/C=US/ST=CA/L=San Francisco/OU=Example/CN=Test Client";URI=http://testclient.example.com;URI=spiffe://example/ns/a;DNS=example.com;DNS=www.example.com`,
		],
		[
			"a proxy whose own certificate has several URI SANs",
			`By=http://frontend.example.com;By=spiffe://example/ns/proxy;Hash=${LEAF_HASH};Cert=${LEAF}`,
		],
		[
			"two elements, the client-facing hop first",
			`By=http://frontend.example.com;Hash=${LEAF_HASH};Cert="${LEAF}";URI=http://testclient.example.com,By=http://backend.example.com;Hash=${sha256Hex(OTHER_PEM)};Cert="${OTHER}";URI=http://frontend.example.com`,
		],
		["Hash= and Cert= alone", `Hash=${LEAF_HASH};Cert=${LEAF}`],
	])("%s", (_name, xfcc) => {
		const parsed = parseEnvoyXfccHeader(xfcc);
		expect(parsed.certPem).toBe(LEAF_PEM);
		if (xfcc.includes(";Chain=")) expect(parsed.chainPem).toBe(INTERMEDIATE_PEM);
	});
});

describe("parsePlainPemHeader", () => {
	it("accepts a literal PEM value and returns it unchanged", () => {
		const result = parsePlainPemHeader(TEST_CERT_PEM);
		expect(result.certPem).toBe(TEST_CERT_PEM);
		expect(result.chainPem).toBeUndefined();
	});

	it("URL-decodes the header value when it is percent-encoded", () => {
		const result = parsePlainPemHeader(ENCODED_CERT);
		expect(result.certPem).toBe(TEST_CERT_PEM);
	});

	it("rejects a header containing multiple PEM blocks", () => {
		// Multi-cert concatenation is explicitly forbidden — operators must use
		// the envoy dialect's Chain= field instead.
		const multiPem = `${TEST_CERT_PEM}\n${TEST_CHAIN_PEM}`;
		expect(() => parsePlainPemHeader(multiPem)).toThrow("multiple PEM blocks");
	});

	it("rejects a second PEM block whose label is not CERTIFICATE", () => {
		const relabelled = TEST_CHAIN_PEM.replaceAll("CERTIFICATE", "X509 CERTIFICATE");
		expect(() => parsePlainPemHeader(`${relabelled}\n${TEST_CERT_PEM}`)).toThrow(
			"multiple PEM blocks",
		);
	});

	it("rejects a single PEM block whose label is not CERTIFICATE", () => {
		const relabelled = TEST_CERT_PEM.replaceAll("CERTIFICATE", "X509 CERTIFICATE");
		expect(() => parsePlainPemHeader(relabelled)).toThrow(
			"does not contain a PEM certificate block",
		);
	});

	it("throws when the header value contains no PEM block at all", () => {
		expect(() => parsePlainPemHeader("not-a-pem-value")).toThrow();
	});

	it("throws when the header value is empty", () => {
		expect(() => parsePlainPemHeader("")).toThrow();
	});

	it("rejects a plain-PEM header that exceeds the raw size cap", () => {
		// Defense-in-depth size cap.
		const oversize = `-----BEGIN CERTIFICATE-----\n${"A".repeat(20 * 1024)}\n-----END CERTIFICATE-----`;
		expect(() => parsePlainPemHeader(oversize)).toThrow("size cap");
	});

	it("applies the raw size cap BEFORE trim/empty check (parity with parseEnvoyXfccHeader)", () => {
		// Don't do trim work on oversize input.
		// A whitespace-only value larger than the raw cap must be rejected by the
		// size check, not the empty check.
		const oversizeWhitespace = " ".repeat(20 * 1024);
		expect(() => parsePlainPemHeader(oversizeWhitespace)).toThrow("size cap");
	});

	it("measures the raw size cap in UTF-8 bytes, not UTF-16 code units (multi-byte cannot bypass)", () => {
		// See the parallel envoy test.
		const multibyte = "あ".repeat(6 * 1024); // 6KB UTF-16 code units = 18KB UTF-8 bytes
		expect(() => parsePlainPemHeader(multibyte)).toThrow("size cap");
	});

	it("normalizes invalid percent-encoding into a plain Error (not URIError)", () => {
		// The safeDecodeURIComponent wrapper.
		// `%C3` is a partial UTF-8 multi-byte sequence — matches isUrlEncoded
		// so triggers decode, but decodeURIComponent throws URIError. The
		// wrapper MUST rethrow as a plain Error.
		const value = "%C3-truncated";
		expect(() => parsePlainPemHeader(value)).toThrow("invalid percent-encoding");
		try {
			parsePlainPemHeader(value);
		} catch (err) {
			expect(err).toBeInstanceOf(Error);
			expect((err as Error).constructor.name).toBe("Error");
		}
	});
});
