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
import { CompactSign, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import { detectAlgorithm } from "../detect.mjs";

/**
 * Build a real compact JWS signed with the given algorithm.
 */
async function makeJws(alg: "EdDSA" | "ES256"): Promise<string> {
	const { privateKey } = await generateKeyPair(alg);
	const payload = new TextEncoder().encode(JSON.stringify({ test: true }));
	return new CompactSign(payload).setProtectedHeader({ alg }).sign(privateKey);
}

describe("detectAlgorithm", () => {
	it("returns explicit body.algorithm when present", () => {
		const body = { algorithm: "custom_alg", did: "did:key:abc" };
		expect(detectAlgorithm(body)).toBe("custom_alg");
	});

	it("prefers explicit body.algorithm over shape-based detection", () => {
		// Even though signature+message are present, explicit algorithm wins
		const body = { algorithm: "custom_alg", signature: "abc", message: "hello" };
		expect(detectAlgorithm(body)).toBe("custom_alg");
	});

	it("falls through to shape-based detection when algorithm is absent", () => {
		const body = { signature: "abc", message: "hello" };
		expect(detectAlgorithm(body)).toBe("ed25519_raw");
	});

	it("returns 'ed25519_raw' when signature and message are present", () => {
		const body = { signature: "abc123", message: "hello" };
		expect(detectAlgorithm(body)).toBe("ed25519_raw");
	});

	it("returns 'ed25519_jws' for a JWS with EdDSA protected header", async () => {
		const jws = await makeJws("EdDSA");
		const body = { jws };
		expect(detectAlgorithm(body)).toBe("ed25519_jws");
	});

	it("returns 'es256_jws' for a JWS with ES256 protected header", async () => {
		const jws = await makeJws("ES256");
		const body = { jws };
		expect(detectAlgorithm(body)).toBe("es256_jws");
	});

	it("returns null when body has neither signature/message nor jws", () => {
		expect(detectAlgorithm({})).toBeNull();
		expect(detectAlgorithm({ did: "did:key:abc" })).toBeNull();
	});

	it("returns null when jws is present but the header has an unknown alg", () => {
		// Craft a fake compact JWS with an unknown alg in the header
		// header: { alg: "RS256" } → base64url
		const fakeHeader = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
		const fakeJws = `${fakeHeader}.payload.sig`;
		const body = { jws: fakeJws };
		expect(detectAlgorithm(body)).toBeNull();
	});

	it("returns null when jws is present but is an invalid/malformed string", () => {
		const body = { jws: "not-a-jws" };
		expect(detectAlgorithm(body)).toBeNull();
	});

	it("prefers ed25519_raw when both signature/message and jws are present", () => {
		// signature + message takes precedence (checked first)
		const body = { signature: "abc", message: "hello", jws: "some.jws.token" };
		expect(detectAlgorithm(body)).toBe("ed25519_raw");
	});

	it("returns 'ed25519_prehash' when signature, message, and prehash='sha256' are present", () => {
		const body = { signature: "abc123", message: "hello", prehash: "sha256" };
		expect(detectAlgorithm(body)).toBe("ed25519_prehash");
	});

	it("returns 'ed25519_raw' when signature and message are present but prehash is absent", () => {
		const body = { signature: "abc123", message: "hello" };
		expect(detectAlgorithm(body)).toBe("ed25519_raw");
	});

	it("returns 'ed25519_raw' when prehash has an unrecognized value", () => {
		const body = { signature: "abc123", message: "hello", prehash: "sha512" };
		expect(detectAlgorithm(body)).toBe("ed25519_raw");
	});
});
