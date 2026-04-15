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
import { Ed25519PrehashVerifier } from "../ed25519Prehash.mjs";

/**
 * Helper: create a pre-hashed signed DID request.
 * 1. Build the JSON message string
 * 2. SHA-256 hash the UTF-8 bytes of the message
 * 3. Sign the 32-byte hash with Ed25519
 */
async function createPrehashSignedRequest(
	did: string,
	privateKey: Uint8Array,
	overrides?: { audience?: string },
): Promise<{ message: string; signature: string; resolvedKey: ExtractedKey }> {
	const publicKeyBytes = await ed.getPublicKeyAsync(privateKey);
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

	// SHA-256 hash the message bytes
	const messageBytes = new TextEncoder().encode(message);
	const hashBuffer = await crypto.subtle.digest("SHA-256", messageBytes);
	const hash = new Uint8Array(hashBuffer);

	// Sign the hash (not the raw message)
	const signatureBytes = await ed.signAsync(hash, privateKey);

	return {
		message,
		signature: Buffer.from(signatureBytes).toString("base64"),
		resolvedKey,
	};
}

describe("Ed25519PrehashVerifier", () => {
	const did = "did:key:z6MkPrehash";
	let privateKey: Uint8Array;

	beforeAll(() => {
		privateKey = ed.utils.randomSecretKey();
	});

	it("returns valid result for correct pre-hashed signature (JWK)", async () => {
		const verifier = new Ed25519PrehashVerifier();
		const { message, signature, resolvedKey } = await createPrehashSignedRequest(did, privateKey);

		const result = await verifier.verify({
			body: { signature, message, prehash: "sha256" },
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
		const verifier = new Ed25519PrehashVerifier();
		const audience = "https://api.example.com";
		const { message, signature, resolvedKey } = await createPrehashSignedRequest(did, privateKey, {
			audience,
		});

		const result = await verifier.verify({
			body: { signature, message, prehash: "sha256" },
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
		const verifier = new Ed25519PrehashVerifier();
		const { message, resolvedKey } = await createPrehashSignedRequest(did, privateKey);

		// Sign with a different key
		const wrongKey = ed.utils.randomSecretKey();
		const messageBytes = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", messageBytes);
		const hash = new Uint8Array(hashBuffer);
		const wrongSigBytes = await ed.signAsync(hash, wrongKey);
		const wrongSignature = Buffer.from(wrongSigBytes).toString("base64");

		const result = await verifier.verify({
			body: { signature: wrongSignature, message, prehash: "sha256" },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_grant");
		}
	});

	it("returns error when signature field is missing", async () => {
		const verifier = new Ed25519PrehashVerifier();
		const { message, resolvedKey } = await createPrehashSignedRequest(did, privateKey);

		const result = await verifier.verify({
			body: { message, prehash: "sha256" },
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
		const verifier = new Ed25519PrehashVerifier();
		const publicKeyBytes = await ed.getPublicKeyAsync(privateKey);
		const x = Buffer.from(publicKeyBytes).toString("base64url");
		const resolvedKey: ExtractedKey = {
			format: "jwk",
			key: { kty: "OKP", crv: "Ed25519", x },
		};

		const result = await verifier.verify({
			body: { signature: "dW51c2Vk", message: "not-json", prehash: "sha256" },
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
		const verifier = new Ed25519PrehashVerifier();
		const { message, signature, resolvedKey } = await createPrehashSignedRequest(
			"did:key:z6MkOther",
			privateKey,
		);

		const result = await verifier.verify({
			body: { signature, message, prehash: "sha256" },
			did, // "did:key:z6MkPrehash" — does not match "did:key:z6MkOther"
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("did");
		}
	});
});
