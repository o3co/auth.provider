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
import {
	decodeProtectedHeader,
	exportPKCS8,
	exportSPKI,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import {
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
} from "#/keys/KeyStore.mjs";

async function generateTestKeyPair(alg: string) {
	const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
	return {
		privateKeyPem: await exportPKCS8(privateKey),
		publicKeyPem: await exportSPKI(publicKey),
	};
}

describe("SymmetricKeyStore", () => {
	const keyStore = createSymmetricKeyStore("test-secret");

	it("has algorithm HS256", () => {
		expect(keyStore.algorithm).toBe("HS256");
	});

	it("has default kid v0", () => {
		expect(keyStore.current.kid).toBe("v0");
	});

	it("accepts custom kid", () => {
		const ks = createSymmetricKeyStore("test-secret", "custom-kid");
		expect(ks.current.kid).toBe("custom-kid");
	});

	it("getSigningKey returns kid and privateKey", () => {
		const signingKey = keyStore.getSigningKey();
		expect(signingKey.kid).toBe("v0");
		expect(signingKey.privateKey).toBeDefined();
	});

	it("getVerificationKey returns key for current kid", () => {
		const key = keyStore.getVerificationKey("v0");
		expect(key).toBeDefined();
	});

	it("getVerificationKey throws for unknown kid", () => {
		expect(() => keyStore.getVerificationKey("unknown")).toThrow();
	});

	it("getVerificationKeys returns current key only (no previous keys)", () => {
		const keys = keyStore.getVerificationKeys();
		expect(keys).toHaveLength(1);
		expect(keys[0].kid).toBe("v0");
	});

	it("current.privateKey and current.publicKey are the same for symmetric", () => {
		expect(keyStore.current.privateKey).toBe(keyStore.current.publicKey);
	});
});

describe("AsymmetricKeyStore", () => {
	it.each([
		"ES256",
		"RS256",
		"EdDSA",
	] as const)("creates %s key store and signs/verifies round-trip", async (alg) => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair(alg);
		const store = await createAsymmetricKeyStore({
			algorithm: alg,
			kid: "k1",
			privateKeyPem,
			publicKeyPem,
		});

		expect(store.algorithm).toBe(alg);
		expect(store.current.kid).toBe("k1");

		// Sign a JWT with the signing key
		const { kid, privateKey } = store.getSigningKey();
		const token = await new SignJWT({ sub: "user1" })
			.setProtectedHeader({ alg, kid })
			.setIssuedAt()
			.sign(privateKey);

		// Verify with the verification key
		const verificationKey = store.getVerificationKey(kid);
		const { payload } = await jwtVerify(token, verificationKey);
		expect(payload.sub).toBe("user1");
	});

	it("includes previous keys in getVerificationKeys", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");

		const store = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k2",
			privateKeyPem: current.privateKeyPem,
			publicKeyPem: current.publicKeyPem,
			previousKeys: [
				{
					kid: "k1",
					publicKeyPem: prev.publicKeyPem,
					expiresAt: new Date(Date.now() + 86400_000), // tomorrow
				},
			],
		});

		const keys = store.getVerificationKeys();
		expect(keys).toHaveLength(2);
		expect(keys.map((k) => k.kid)).toContain("k1");
		expect(keys.map((k) => k.kid)).toContain("k2");
	});

	it("excludes expired previous keys from getVerificationKeys", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");

		const store = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k2",
			privateKeyPem: current.privateKeyPem,
			publicKeyPem: current.publicKeyPem,
			previousKeys: [
				{
					kid: "k1",
					publicKeyPem: prev.publicKeyPem,
					expiresAt: new Date(Date.now() - 1000), // already expired
				},
			],
		});

		const keys = store.getVerificationKeys();
		expect(keys).toHaveLength(1);
		expect(keys[0].kid).toBe("k2");
	});

	it("token signed with previous key can be verified", async () => {
		// Generate two key pairs — simulate rotation
		const oldPair = await generateTestKeyPair("ES256");
		const newPair = await generateTestKeyPair("ES256");

		// Sign a token with the old key
		const { importPKCS8 } = await import("jose");
		const oldSigningKey = await importPKCS8(oldPair.privateKeyPem, "ES256");
		const token = await new SignJWT({ sub: "user-old" })
			.setProtectedHeader({ alg: "ES256", kid: "k-old" })
			.setIssuedAt()
			.sign(oldSigningKey);

		// Create store with newPair as current, oldPair as previous
		const store = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k-new",
			privateKeyPem: newPair.privateKeyPem,
			publicKeyPem: newPair.publicKeyPem,
			previousKeys: [
				{
					kid: "k-old",
					publicKeyPem: oldPair.publicKeyPem,
					expiresAt: new Date(Date.now() + 86400_000),
				},
			],
		});

		// Verify old token with previous key
		const header = decodeProtectedHeader(token);
		if (!header.kid) throw new Error("Expected kid in header");
		const verificationKey = store.getVerificationKey(header.kid);
		const { payload } = await jwtVerify(token, verificationKey);
		expect(payload.sub).toBe("user-old");
	});

	it("throws on duplicate kid between current and previousKeys", async () => {
		const keys = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");

		await expect(
			createAsymmetricKeyStore({
				algorithm: "ES256",
				kid: "same-kid",
				privateKeyPem: keys.privateKeyPem,
				publicKeyPem: keys.publicKeyPem,
				previousKeys: [
					{
						kid: "same-kid",
						publicKeyPem: prev.publicKeyPem,
						expiresAt: new Date(Date.now() + 86400000),
					},
				],
			}),
		).rejects.toThrow("Duplicate kid");
	});

	it("throws on duplicate kid within previousKeys", async () => {
		const keys = await generateTestKeyPair("ES256");
		const prev1 = await generateTestKeyPair("ES256");
		const prev2 = await generateTestKeyPair("ES256");

		await expect(
			createAsymmetricKeyStore({
				algorithm: "ES256",
				kid: "current",
				privateKeyPem: keys.privateKeyPem,
				publicKeyPem: keys.publicKeyPem,
				previousKeys: [
					{
						kid: "dup",
						publicKeyPem: prev1.publicKeyPem,
						expiresAt: new Date(Date.now() + 86400000),
					},
					{
						kid: "dup",
						publicKeyPem: prev2.publicKeyPem,
						expiresAt: new Date(Date.now() + 86400000),
					},
				],
			}),
		).rejects.toThrow("Duplicate kid");
	});

	it("throws for unknown kid", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("ES256");
		const store = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k1",
			privateKeyPem,
			publicKeyPem,
		});

		expect(() => store.getVerificationKey("unknown")).toThrow("Unknown kid: unknown");
	});

	it("throws for expired kid", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");

		const store = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k2",
			privateKeyPem: current.privateKeyPem,
			publicKeyPem: current.publicKeyPem,
			previousKeys: [
				{
					kid: "k1",
					publicKeyPem: prev.publicKeyPem,
					expiresAt: new Date(Date.now() - 1000),
				},
			],
		});

		expect(() => store.getVerificationKey("k1")).toThrow();
	});
});

