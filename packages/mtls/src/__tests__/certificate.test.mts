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
import { parseDerToCertificate } from "#/certificate.mjs";

/**
 * Same fixed test certificate used in thumbprint.test.mts — a committed
 * fixture so tests are deterministic without network access or keygen.
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

const TEST_CERT_DER = new X509Certificate(TEST_CERT_PEM).raw as unknown as Uint8Array;

describe("parseDerToCertificate", () => {
	it("populates all four parsed fields from a valid DER certificate", () => {
		const cert = parseDerToCertificate(TEST_CERT_DER);
		// All four diagnostic fields must be present and non-empty strings.
		expect(typeof cert.parsed.subject).toBe("string");
		expect(cert.parsed.subject.length).toBeGreaterThan(0);
		expect(typeof cert.parsed.issuer).toBe("string");
		expect(cert.parsed.issuer.length).toBeGreaterThan(0);
		expect(typeof cert.parsed.notBefore).toBe("string");
		expect(cert.parsed.notBefore.length).toBeGreaterThan(0);
		expect(typeof cert.parsed.notAfter).toBe("string");
		expect(cert.parsed.notAfter.length).toBeGreaterThan(0);
	});

	it("preserves the input DER bytes as the der field (same reference)", () => {
		const cert = parseDerToCertificate(TEST_CERT_DER);
		// The `der` field must be the same reference — no copy (for thumbprinting efficiency).
		expect(cert.der).toBe(TEST_CERT_DER);
	});

	it("attaches the chain when provided and omits the chain property when not provided", () => {
		const fakeDer = new Uint8Array([0x30, 0x01]);
		const certWithChain = parseDerToCertificate(TEST_CERT_DER, [fakeDer]);
		expect(certWithChain.chain).toHaveLength(1);
		expect(certWithChain.chain?.[0]).toBe(fakeDer);

		const certWithoutChain = parseDerToCertificate(TEST_CERT_DER);
		expect(certWithoutChain.chain).toBeUndefined();
	});

	it("throws on malformed DER bytes", () => {
		// `new X509Certificate(der)` will throw on garbage input — the call site
		// wraps this into MtlsError("cert_decode_failed") but parseDerToCertificate
		// itself propagates the raw error per spec §6.3.
		const garbage = new Uint8Array([0x00, 0x01, 0x02]);
		expect(() => parseDerToCertificate(garbage)).toThrow();
	});
});
