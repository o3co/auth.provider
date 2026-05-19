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
import { describe, expect, it } from "vitest";
import { derToPem, pemToDer } from "#/pem.mjs";

/**
 * Fixed test certificate DER — extracted from the same P-256 self-signed cert
 * used in certificate.test.mts and thumbprint.test.mts.
 * Using a real X509Certificate to get structurally valid DER for roundtrip tests.
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

const TEST_CERT_DER: Uint8Array = new X509Certificate(TEST_CERT_PEM).raw;

describe("derToPem", () => {
	it("wraps DER bytes in correct BEGIN/END CERTIFICATE markers", () => {
		const pem = derToPem(new Uint8Array([0x30, 0x01, 0x00]));
		expect(pem).toContain("-----BEGIN CERTIFICATE-----");
		expect(pem).toContain("-----END CERTIFICATE-----");
	});

	it("uses 64-character line wrapping per RFC 7468 §2", () => {
		// 60 bytes → 80 base64 chars → 2 lines of ≤64 chars each.
		const der = new Uint8Array(60).fill(0xab);
		const pem = derToPem(der);
		const lines = pem.split("\n").slice(1, -1); // strip BEGIN/END lines
		for (const line of lines) {
			expect(line.length).toBeLessThanOrEqual(64);
		}
	});

	it("accepts a custom type label for non-certificate PEM blocks", () => {
		const der = new Uint8Array([0x30]);
		const pem = derToPem(der, "PUBLIC KEY");
		expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
		expect(pem).toContain("-----END PUBLIC KEY-----");
	});
});

describe("pemToDer", () => {
	it("decodes PEM back to the original DER bytes (roundtrip via real X509 cert)", () => {
		// Re-encode the cert DER to PEM and decode back — both directions exercised.
		// Compare as Uint8Array (Buffer is a subclass) to avoid toEqual type mismatch.
		const rePem = derToPem(TEST_CERT_DER);
		const decoded = pemToDer(rePem);
		expect(Buffer.from(decoded).equals(Buffer.from(TEST_CERT_DER))).toBe(true);
	});

	it("throws when BEGIN marker is missing", () => {
		const noBEgin = "MIID...base64...==\n-----END CERTIFICATE-----";
		expect(() => pemToDer(noBEgin)).toThrow("BEGIN");
	});

	it("throws when END marker is missing", () => {
		const noEnd = "-----BEGIN CERTIFICATE-----\nMIID...base64...==";
		expect(() => pemToDer(noEnd)).toThrow("END");
	});

	it("throws when BEGIN and END type labels do not match", () => {
		const mismatched = "-----BEGIN CERTIFICATE-----\nMIID\n-----END PRIVATE KEY-----";
		expect(() => pemToDer(mismatched)).toThrow("mismatch");
	});

	it("decodes the original test certificate PEM directly", () => {
		// Verify that our pemToDer handles the fixed test cert PEM verbatim.
		// Compare via Buffer.equals to avoid vitest's Uint8Array vs Buffer toEqual mismatch.
		const decoded = pemToDer(TEST_CERT_PEM);
		expect(Buffer.from(decoded).equals(Buffer.from(TEST_CERT_DER))).toBe(true);
	});
});
