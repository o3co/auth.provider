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
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportSPKI, exportPKCS8, SignJWT, jwtVerify, decodeProtectedHeader } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAsymmetricKeyStore, createKeyStoreFromConfig, createSymmetricKeyStore } from "../KeyStore.mjs";
import type { JwtConfig } from "../KeyStore.mjs";

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
	it.each(["ES256", "RS256", "EdDSA"] as const)("creates %s key store and signs/verifies round-trip", async (alg) => {
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

describe("createKeyStoreFromConfig", () => {
	let tmpDir: string;

	beforeAll(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "keystore-test-"));
	});

	afterAll(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("HS256 with secret creates symmetric key store", async () => {
		const config: JwtConfig = {
			algorithm: "HS256",
			secret: "my-test-secret",
			kid: "v0",
			previousKeys: [],
		};
		const store = await createKeyStoreFromConfig(config);
		expect(store.algorithm).toBe("HS256");
		expect(store.current.kid).toBe("v0");
	});

	it("HS256 without secret throws", async () => {
		const config: JwtConfig = {
			algorithm: "HS256",
			kid: "v0",
			previousKeys: [],
		};
		await expect(createKeyStoreFromConfig(config)).rejects.toThrow();
	});

	it("ES256 with privateKey and publicKey creates asymmetric key store", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("ES256");
		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "k1",
			privateKey: privateKeyPem,
			publicKey: publicKeyPem,
			previousKeys: [],
		};
		const store = await createKeyStoreFromConfig(config);
		expect(store.algorithm).toBe("ES256");

		// Verify round-trip
		const { kid, privateKey } = store.getSigningKey();
		const token = await new SignJWT({ sub: "u1" })
			.setProtectedHeader({ alg: "ES256", kid })
			.sign(privateKey);
		const verificationKey = store.getVerificationKey(kid);
		const { payload } = await jwtVerify(token, verificationKey);
		expect(payload.sub).toBe("u1");
	});

	it("RS256 with keys creates asymmetric key store", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("RS256");
		const config: JwtConfig = {
			algorithm: "RS256",
			kid: "r1",
			privateKey: privateKeyPem,
			publicKey: publicKeyPem,
			previousKeys: [],
		};
		const store = await createKeyStoreFromConfig(config);
		expect(store.algorithm).toBe("RS256");
	});

	it("ES256 without privateKey throws", async () => {
		const { publicKeyPem } = await generateTestKeyPair("ES256");
		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "k1",
			publicKey: publicKeyPem,
			previousKeys: [],
		};
		await expect(createKeyStoreFromConfig(config)).rejects.toThrow();
	});

	it("ES256 without publicKey throws", async () => {
		const { privateKeyPem } = await generateTestKeyPair("ES256");
		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "k1",
			privateKey: privateKeyPem,
			previousKeys: [],
		};
		await expect(createKeyStoreFromConfig(config)).rejects.toThrow();
	});

	it("reads keys from file paths", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("ES256");
		const privPath = join(tmpDir, "private.pem");
		const pubPath = join(tmpDir, "public.pem");
		writeFileSync(privPath, privateKeyPem);
		writeFileSync(pubPath, publicKeyPem);

		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "f1",
			privateKeyPath: privPath,
			publicKeyPath: pubPath,
			previousKeys: [],
		};
		const store = await createKeyStoreFromConfig(config);
		expect(store.algorithm).toBe("ES256");
		expect(store.current.kid).toBe("f1");
	});

	it("file path takes priority over PEM string", async () => {
		const pair1 = await generateTestKeyPair("ES256");
		const pair2 = await generateTestKeyPair("ES256");
		const privPath = join(tmpDir, "private-priority.pem");
		const pubPath = join(tmpDir, "public-priority.pem");
		writeFileSync(privPath, pair1.privateKeyPem);
		writeFileSync(pubPath, pair1.publicKeyPem);

		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "p1",
			privateKey: pair2.privateKeyPem,  // different key — should be ignored
			privateKeyPath: privPath,
			publicKey: pair2.publicKeyPem,
			publicKeyPath: pubPath,
			previousKeys: [],
		};
		const store = await createKeyStoreFromConfig(config);

		// Sign with store and verify with pair1's public key (from file)
		const { kid, privateKey } = store.getSigningKey();
		const token = await new SignJWT({ sub: "priority" })
			.setProtectedHeader({ alg: "ES256", kid })
			.sign(privateKey);

		const { importSPKI: importSPKIFn } = await import("jose");
		const pubKeyFromFile = await importSPKIFn(pair1.publicKeyPem, "ES256");
		const { payload } = await jwtVerify(token, pubKeyFromFile);
		expect(payload.sub).toBe("priority");
	});

	it("previousKeys with expiresAt loaded correctly", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");

		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "k2",
			privateKey: current.privateKeyPem,
			publicKey: current.publicKeyPem,
			previousKeys: [
				{
					kid: "k1",
					publicKey: prev.publicKeyPem,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		};
		const store = await createKeyStoreFromConfig(config);
		const keys = store.getVerificationKeys();
		expect(keys).toHaveLength(2);
		expect(keys.map((k) => k.kid)).toContain("k1");
	});

	it("previousKeys with publicKeyPath reads from file", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");
		const prevPubPath = join(tmpDir, "prev-public.pem");
		writeFileSync(prevPubPath, prev.publicKeyPem);

		const config: JwtConfig = {
			algorithm: "ES256",
			kid: "k2",
			privateKey: current.privateKeyPem,
			publicKey: current.publicKeyPem,
			previousKeys: [
				{
					kid: "k1",
					publicKeyPath: prevPubPath,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		};
		const store = await createKeyStoreFromConfig(config);
		const keys = store.getVerificationKeys();
		expect(keys).toHaveLength(2);
	});
});
