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

import { JwsVerifier } from "../jws.mjs";

/**
 * Helper: create a signed JWS for a DID message using a real key pair.
 */
async function createSignedJws(
	alg: "EdDSA" | "ES256" | "ES256K",
	did: string,
	overrides?: { audience?: string; didOverride?: string },
): Promise<{ jws: string; publicKey: string }> {
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
		publicKey: JSON.stringify(jwk),
	};
}

describe("JwsVerifier", () => {
	const did = "did:key:z6MkTestJws";

	it("returns valid result for correct EdDSA JWS", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws, publicKey } = await createSignedJws("EdDSA", did);

		const result = await verifier.verify({
			body: { jws, publicKey },
			did,
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
		const { jws, publicKey } = await createSignedJws("ES256", did);

		const result = await verifier.verify({
			body: { jws, publicKey },
			did,
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
		const { jws, publicKey } = await createSignedJws("ES256", did);

		const result = await verifier.verify({
			body: { jws, publicKey },
			did,
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

		const result = await verifier.verify({
			body: { publicKey: '{"kty":"OKP"}' },
			did,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("jws");
		}
	});

	it("returns error when publicKey field is missing from body", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws } = await createSignedJws("EdDSA", did);

		const result = await verifier.verify({
			body: { jws },
			did,
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("publicKey");
		}
	});

	it("returns error when payload.did does not match ctx.did", async () => {
		const verifier = new JwsVerifier("EdDSA");
		const { jws, publicKey } = await createSignedJws("EdDSA", did, {
			didOverride: "did:key:z6MkDifferent",
		});

		const result = await verifier.verify({
			body: { jws, publicKey },
			did, // "did:key:z6MkTestJws" — does not match "did:key:z6MkDifferent"
		});

		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toBe("invalid_request");
			expect(result.errorDescription).toContain("did");
		}
	});
});
