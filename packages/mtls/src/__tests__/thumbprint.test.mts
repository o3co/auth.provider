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
import { computeCertThumbprint } from "#/thumbprint.mjs";

/**
 * Fixed test certificate (P-256, CN=test, self-signed, valid 2026-05-19).
 *
 * This PEM is committed as a test fixture for deterministic thumbprint
 * assertions. The cert is not trusted anywhere — it exists purely to pin
 * the thumbprint computation against a known value.
 *
 * Pre-computed expected thumbprint (SHA-256 of DER, base64url, no padding):
 *   ixxC3Iu02KfsoIX8SaMQS0-nHDkhl4CtXw-kKsC1Lws
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
const EXPECTED_THUMBPRINT = "ixxC3Iu02KfsoIX8SaMQS0-nHDkhl4CtXw-kKsC1Lws";

describe("computeCertThumbprint — RFC 8705 §3.1 DER SHA-256 thumbprint", () => {
	it("produces the pre-computed thumbprint for the fixed test certificate", () => {
		// Pins the computation against a known DER → thumbprint mapping.
		// If this test fails, the hash function or encoding changed.
		const thumbprint = computeCertThumbprint(TEST_CERT_DER);
		expect(thumbprint).toBe(EXPECTED_THUMBPRINT);
	});

	it("output is base64url-encoded — no +, /, or = characters", () => {
		const thumbprint = computeCertThumbprint(TEST_CERT_DER);
		// base64url alphabet uses - and _ instead of + and /; no = padding.
		expect(thumbprint).not.toMatch(/[+/=]/);
		expect(thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it("output length is 43 characters (SHA-256 base64url without padding)", () => {
		// SHA-256 produces 32 bytes → 256 bits → ceil(256/6) = 43 base64url chars
		// (no trailing = because 32 * 8 = 256 is divisible by 6 with 2 bits left,
		// yielding 43 full base64url characters and 0 padding characters).
		const thumbprint = computeCertThumbprint(TEST_CERT_DER);
		expect(thumbprint.length).toBe(43);
	});

	it("is deterministic — same DER input always yields the same thumbprint", () => {
		const first = computeCertThumbprint(TEST_CERT_DER);
		const second = computeCertThumbprint(TEST_CERT_DER);
		expect(first).toBe(second);
	});

	it("produces different thumbprints for different DER inputs", () => {
		// A one-byte change in the DER produces a completely different hash.
		const mutated = Uint8Array.from(TEST_CERT_DER);
		mutated[0] ^= 0xff; // flip all bits in the first byte
		const original = computeCertThumbprint(TEST_CERT_DER);
		const modified = computeCertThumbprint(mutated);
		expect(original).not.toBe(modified);
	});
});
