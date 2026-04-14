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
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import type { ExtractedKey } from "../../resolver/extractKey.mjs";
import { JwsVerifier } from "../jws.mjs";

/**
 * Helper: create a signed JWS for a DID message using a real key pair.
 * Returns jws and resolvedKey (JWK format).
 */
async function createSignedJws(
	alg: "EdDSA" | "ES256" | "ES256K",
	did: string,
	overrides?: { audience?: string; didOverride?: string },
): Promise<{ jws: string; resolvedKey: ExtractedKey }> {
	const { privateKey, publicKey } = await generateKeyPair(alg);
	const jwk = await exportJWK(publicKey);

	const payload = JSON.stringify({
		did: overrides?.didOverride ?? did,
		timestamp: new Date().toISOString(),
		nonce: crypto.randomUUID(),
		...(overrides?.audience ? { audience: overrides.audience } : {}),
	});

	const jws = await new CompactSign(new TextEncoder().encode(payload))
		.setProtectedHeader({ alg })
		.sign(privateKey);

	return {
		jws,
		resolvedKey: { format: "jwk", key: jwk },
	};
}

describe("JwsVerifier", () => {
	const did = "did:key:z6MkTestJws";

	it("returns valid result for correct EdDSA JWS", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws, resolvedKey } = await createSignedJws("EdDSA", did);

		const result = await verifier.verify({
			body: { jws },
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

	it("returns valid result for correct ES256 JWS", async () => {
		const verifier = new JwsVerifier("ES256");
		const { jws, resolvedKey } = await createSignedJws("ES256", did);

		const result = await verifier.verify({
			body: { jws },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.subject).toBe(did);
			expect(result.parsedMessage.did).toBe(did);
		}
	});

	it("returns error when JWS algorithm does not match expected", async () => {
		const verifier = new JwsVerifier("EdDSA");
		// Sign with ES256 but verifier expects EdDSA
		const { jws, resolvedKey } = await createSignedJws("ES256", did);

		const result = await verifier.verify({
			body: { jws },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("algorithm");
		}
	});

	// ES256K (secp256k1) is not supported by Node.js WebCrypto / jose.generateKeyPair.
	// The JwsVerifier handles it via the same compactVerify path as ES256,
	// so it is covered by the ES256 tests structurally. Skip until secp256k1 support
	// is available in the runtime or a dedicated library is added.
	it.todo("returns valid result for correct ES256K JWS");

	it("returns error when jws field is missing from body", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const resolvedKey: ExtractedKey = { format: "jwk", key: { kty: "OKP" } };

		const result = await verifier.verify({
			body: {},
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("jws");
		}
	});

	it("returns error when resolvedKey is multibase (not supported for JWS)", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws } = await createSignedJws("EdDSA", did);
		const resolvedKey: ExtractedKey = {
			format: "multibase",
			key: "z6MkSomeKey",
		};

		const result = await verifier.verify({
			body: { jws },
			did,
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("multibase");
		}
	});

	it("returns error when payload.did does not match ctx.did", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws, resolvedKey } = await createSignedJws("EdDSA", did, {
			didOverride: "did:key:z6MkDifferent",
		});

		const result = await verifier.verify({
			body: { jws },
			did, // "did:key:z6MkTestJws" — does not match "did:key:z6MkDifferent"
			resolvedKey,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("did");
		}
	});
});
