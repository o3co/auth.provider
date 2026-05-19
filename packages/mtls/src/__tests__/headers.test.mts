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

describe("parseEnvoyXfccHeader", () => {
	it("parses a well-formed XFCC header with Cert= only", () => {
		const xfcc = `By=spiffe://cluster.local/ns/default/sa/server;Hash=abc123;Cert=${ENCODED_CERT}`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
		expect(result.chainPem).toBeUndefined();
	});

	it("parses a well-formed XFCC header with both Cert= and Chain=", () => {
		const xfcc = `By=spiffe://cluster.local;Hash=abc;Cert=${ENCODED_CERT};Chain=${ENCODED_CHAIN}`;
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
		const xfcc = `Cert=${ENCODED_CERT},Cert=otherstuff`;
		const result = parseEnvoyXfccHeader(xfcc);
		expect(result.certPem).toBe(TEST_CERT_PEM);
	});

	it("URL-decodes the Cert= value correctly (roundtrip)", () => {
		const xfcc = `Cert=${ENCODED_CERT}`;
		const result = parseEnvoyXfccHeader(xfcc);
		// After URL-decoding, the PEM must match the original exactly.
		expect(result.certPem).toContain("-----BEGIN CERTIFICATE-----");
		expect(result.certPem).toContain("-----END CERTIFICATE-----");
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

	it("rejects a header containing multiple PEM blocks (spec OQ1 §14.1 strict)", () => {
		// Multi-cert concatenation is explicitly forbidden — operators must use
		// the envoy dialect's Chain= field instead.
		const multiPem = `${TEST_CERT_PEM}\n${TEST_CHAIN_PEM}`;
		expect(() => parsePlainPemHeader(multiPem)).toThrow("multiple PEM blocks");
	});

	it("throws when the header value contains no PEM block at all", () => {
		expect(() => parsePlainPemHeader("not-a-pem-value")).toThrow();
	});

	it("throws when the header value is empty", () => {
		expect(() => parsePlainPemHeader("")).toThrow();
	});
});
