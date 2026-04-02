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
import { generateKeyPair, exportSPKI, exportPKCS8, jwtVerify, decodeProtectedHeader } from "jose";
import { createKeyStoreFromConfig } from "../KeyStore.mjs";
import { generateToken } from "../../grants/token.mjs";

async function generateTestKeyPair(alg: string) {
	const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
	return {
		privateKeyPem: await exportPKCS8(privateKey),
		publicKeyPem: await exportSPKI(publicKey),
	};
}

describe("Integration: generateToken + asymmetric KeyStore", () => {
	it.each(["ES256", "RS256", "EdDSA"] as const)(
		"%s: createKeyStoreFromConfig -> generateToken -> jwtVerify round-trip",
		async (alg) => {
			const { privateKeyPem, publicKeyPem } = await generateTestKeyPair(alg);

			const keyStore = await createKeyStoreFromConfig({
				algorithm: alg,
				kid: `${alg.toLowerCase()}-v1`,
				privateKey: privateKeyPem,
				publicKey: publicKeyPem,
				previousKeys: [],
			});

			const token = await generateToken(
				{ sub: "user-123", role: "admin" },
				{
					keyStore,
					issuer: "https://auth.example.com",
					audience: "https://api.example.com",
					scopes: ["read", "write"],
					expiresIn: 3600,
					type: "access",
				},
			);

			expect(token.token).toBeDefined();
			expect(token.issuer).toBe("https://auth.example.com");
			expect(token.audience).toBe("https://api.example.com");
			expect(token.scopes).toEqual(["read", "write"]);
			expect(token.expiresIn).toBe(3600);
			expect(token.type).toBe("access");

			// Verify the JWT header
			const header = decodeProtectedHeader(token.token);
			expect(header.alg).toBe(alg);
			expect(header.kid).toBe(`${alg.toLowerCase()}-v1`);

			// Verify the JWT payload using the KeyStore's verification key
			const verificationKey = keyStore.getVerificationKey(header.kid!);
			const { payload } = await jwtVerify(token.token, verificationKey, {
				issuer: "https://auth.example.com",
				audience: "https://api.example.com",
			});

			expect(payload.sub).toBe("user-123");
			expect(payload.role).toBe("admin");
			expect(payload.scopes).toEqual(["read", "write"]);
			expect(payload.type).toBe("access");
			expect(payload.iss).toBe("https://auth.example.com");
			expect(payload.aud).toBe("https://api.example.com");
			expect(payload.iat).toBeTypeOf("number");
			expect(payload.exp).toBeTypeOf("number");
		},
	);

	it("key rotation: token signed with old key is verifiable after rotation", async () => {
		const oldPair = await generateTestKeyPair("ES256");
		const newPair = await generateTestKeyPair("ES256");

		// Step 1: Create KeyStore with old key and sign a token
		const oldKeyStore = await createKeyStoreFromConfig({
			algorithm: "ES256",
			kid: "k-old",
			privateKey: oldPair.privateKeyPem,
			publicKey: oldPair.publicKeyPem,
			previousKeys: [],
		});

		const oldToken = await generateToken(
			{ sub: "user-456", role: "viewer" },
			{
				keyStore: oldKeyStore,
				issuer: "https://auth.example.com",
				expiresIn: 7200,
			},
		);

		// Verify old token works with old KeyStore
		const oldHeader = decodeProtectedHeader(oldToken.token);
		expect(oldHeader.kid).toBe("k-old");

		const oldVerificationKey = oldKeyStore.getVerificationKey("k-old");
		const { payload: oldPayload } = await jwtVerify(oldToken.token, oldVerificationKey);
		expect(oldPayload.sub).toBe("user-456");

		// Step 2: Rotate keys — new KeyStore with old key in previousKeys
		const newKeyStore = await createKeyStoreFromConfig({
			algorithm: "ES256",
			kid: "k-new",
			privateKey: newPair.privateKeyPem,
			publicKey: newPair.publicKeyPem,
			previousKeys: [
				{
					kid: "k-old",
					publicKey: oldPair.publicKeyPem,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		});

		// Step 3: Verify old token still works with new KeyStore
		const rotatedVerificationKey = newKeyStore.getVerificationKey(oldHeader.kid!);
		const { payload: rotatedPayload } = await jwtVerify(oldToken.token, rotatedVerificationKey);
		expect(rotatedPayload.sub).toBe("user-456");
		expect(rotatedPayload.role).toBe("viewer");

		// Step 4: New tokens are signed with the new key
		const newToken = await generateToken(
			{ sub: "user-789" },
			{ keyStore: newKeyStore, expiresIn: 3600 },
		);

		const newHeader = decodeProtectedHeader(newToken.token);
		expect(newHeader.kid).toBe("k-new");

		const newVerificationKey = newKeyStore.getVerificationKey("k-new");
		const { payload: newPayload } = await jwtVerify(newToken.token, newVerificationKey);
		expect(newPayload.sub).toBe("user-789");
	});

	it("key rotation: expired previous key is rejected", async () => {
		const oldPair = await generateTestKeyPair("RS256");
		const newPair = await generateTestKeyPair("RS256");

		// Sign a token with old key
		const oldKeyStore = await createKeyStoreFromConfig({
			algorithm: "RS256",
			kid: "r-old",
			privateKey: oldPair.privateKeyPem,
			publicKey: oldPair.publicKeyPem,
			previousKeys: [],
		});

		const oldToken = await generateToken(
			{ sub: "user-expired" },
			{ keyStore: oldKeyStore, expiresIn: 3600 },
		);

		// Rotate with expired previous key
		const newKeyStore = await createKeyStoreFromConfig({
			algorithm: "RS256",
			kid: "r-new",
			privateKey: newPair.privateKeyPem,
			publicKey: newPair.publicKeyPem,
			previousKeys: [
				{
					kid: "r-old",
					publicKey: oldPair.publicKeyPem,
					expiresAt: new Date(Date.now() - 1000).toISOString(),
				},
			],
		});

		// Attempting to verify with expired previous key should throw
		expect(() => newKeyStore.getVerificationKey("r-old")).toThrow("Expired kid: r-old");
	});
});
