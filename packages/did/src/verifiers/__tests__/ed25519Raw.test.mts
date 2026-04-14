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
import * as ed from "@noble/ed25519";
import { beforeAll, describe, expect, it } from "vitest";

import type { ExtractedKey } from "../../resolver/extractKey.mjs";
import { Ed25519RawVerifier } from "../ed25519Raw.mjs";

/**
 * Helper: create a signed DID request using a real Ed25519 key pair.
 * Returns message, signature, and resolvedKey (JWK format with x field = base64url raw public key).
 */
async function createSignedRequest(
	did: string,
	privateKey: Uint8Array,
	overrides?: { audience?: string },
): Promise<{ message: string; signature: string; resolvedKey: ExtractedKey }> {
	const publicKeyBytes = await ed.getPublicKeyAsync(privateKey);
	// Encode as base64url for the JWK x field
	const x = Buffer.from(publicKeyBytes).toString("base64url");
	const resolvedKey: ExtractedKey = {
		format: "jwk",
		key: { kty: "OKP", crv: "Ed25519", x },
	};

	const message = JSON.stringify({
		did,
		timestamp: new Date().toISOString(),
		nonce: crypto.randomUUID(),
		...(overrides?.audience ? { audience: overrides.audience } : {}),
	});
	const messageBytes = new TextEncoder().encode(message);
	const signatureBytes = await ed.signAsync(messageBytes, privateKey);

	return {
		message,
		signature: Buffer.from(signatureBytes).toString("base64"),
		resolvedKey,
	};
}

describe("Ed25519RawVerifier", () => {
	const did = "did:key:z6MkTest";
	let privateKey: Uint8Array;

	beforeAll(() => {
		privateKey = ed.utils.randomSecretKey();
	});

	it("returns valid result for correct signature (resolvedKey JWK)", async () => {
		const verifier = new Ed25519RawVerifier();
		const { message, signature, resolvedKey } = await createSignedRequest(did, privateKey);

		const result = await verifier.verify({
			body: { signature, message },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.subject).toBe(did);
			expect(result.parsedMessage.did).toBe(did);
			expect(result.parsedMessage.nonce).toBeDefined();
			expect(result.parsedMessage.timestamp).toBeDefined();
		}
	});

	it("returns valid result with audience when present", async () => {
		const verifier = new Ed25519RawVerifier();
		const audience = "https://api.example.com";
		const { message, signature, resolvedKey } = await createSignedRequest(did, privateKey, {
			audience,
		});

		const result = await verifier.verify({
			body: { signature, message },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.audience).toBe(audience);
			expect(result.parsedMessage.audience).toBe(audience);
		}
	});

	it("returns invalid when signature is wrong", async () => {
		const verifier = new Ed25519RawVerifier();
		const { message, resolvedKey } = await createSignedRequest(did, privateKey);
		// Sign with a different key
		const wrongKey = ed.utils.randomSecretKey();
		const wrongSigBytes = await ed.signAsync(new TextEncoder().encode(message), wrongKey);
		const wrongSignature = Buffer.from(wrongSigBytes).toString("base64");

		const result = await verifier.verify({
			body: { signature: wrongSignature, message },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_grant");
		}
	});

	it("returns error when signature field is missing", async () => {
		const verifier = new Ed25519RawVerifier();
		const { message, resolvedKey } = await createSignedRequest(did, privateKey);

		const result = await verifier.verify({
			body: { message },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("signature");
		}
	});

	it("returns error when message is not valid JSON", async () => {
		const verifier = new Ed25519RawVerifier();
		const publicKeyBytes = await ed.getPublicKeyAsync(privateKey);
		const x = Buffer.from(publicKeyBytes).toString("base64url");
		const resolvedKey: ExtractedKey = { format: "jwk", key: { kty: "OKP", crv: "Ed25519", x } };

		const result = await verifier.verify({
			body: { signature: "dW51c2Vk", message: "not-json" },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("JSON");
		}
	});

	it("returns error when message.did does not match ctx.did", async () => {
		const verifier = new Ed25519RawVerifier();
		const { message, signature, resolvedKey } = await createSignedRequest(
			"did:key:z6MkOther",
			privateKey,
		);

		const result = await verifier.verify({
			body: { signature, message },
			did, // "did:key:z6MkTest" — does not match "did:key:z6MkOther"
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("did");
		}
	});
});
