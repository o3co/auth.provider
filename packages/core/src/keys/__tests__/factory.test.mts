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
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AdapterFactoryError } from "#/adapters/AdapterFactory.mjs";
import { createKeyStoreFactory, registerBuiltinKeyStores } from "#/keys/factory.mjs";

async function generateTestKeyPair(alg: string) {
	const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
	return {
		privateKeyPem: await exportPKCS8(privateKey),
		publicKeyPem: await exportSPKI(publicKey),
	};
}

describe("createKeyStoreFactory", () => {
	it("returns a factory with no registered types by default", () => {
		const factory = createKeyStoreFactory();

		expect(factory.registeredTypes()).toEqual([]);
	});

	it("rejects with AdapterFactoryError for an unknown type", async () => {
		const factory = createKeyStoreFactory();

		await expect(factory.create({ type: "local" })).rejects.toSatisfy((err: unknown) => {
			if (!(err instanceof AdapterFactoryError)) return false;
			return (
				err.name === "AdapterFactoryError" && err.reason === "unknown" && err.kind === "KeyStore"
			);
		});
	});
});

describe("registerBuiltinKeyStores - local HS256", () => {
	it("registers 'local' type", () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		expect(factory.registeredTypes()).toContain("local");
	});

	it("builds HS256 KeyStore with secret", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "HS256",
			kid: "v1",
			secret: "s3cret",
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("HS256");
		expect(keyStore.current.kid).toBe("v1");
	});

	it("throws clear error when HS256 secret is missing", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({ type: "local", algorithm: "HS256", kid: "v1", previousKeys: [] }),
		).rejects.toThrow(/secret is required for HS256/i);
	});

	it("throws when HS256 secret is an empty string", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "HS256",
				kid: "v1",
				secret: "",
				previousKeys: [],
			}),
		).rejects.toThrow(/secret is required for HS256/i);
	});
});

describe("registerBuiltinKeyStores - local asymmetric", () => {
	let tmpDir: string;

	beforeAll(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "factory-asym-test-"));
	});

	afterAll(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("builds RS256 KeyStore from PEM strings", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("RS256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "RS256",
			kid: "v1",
			privateKey: privateKeyPem,
			publicKey: publicKeyPem,
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("RS256");
		expect(keyStore.current.kid).toBe("v1");
	});

	it("builds ES256 KeyStore from PEM strings", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("ES256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "ES256",
			kid: "v1",
			privateKey: privateKeyPem,
			publicKey: publicKeyPem,
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("ES256");
		expect(keyStore.current.kid).toBe("v1");
	});

	it("builds EdDSA KeyStore from PEM strings", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("EdDSA");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "EdDSA",
			kid: "v1",
			privateKey: privateKeyPem,
			publicKey: publicKeyPem,
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("EdDSA");
		expect(keyStore.current.kid).toBe("v1");
	});

	it("throws when asymmetric privateKey/privateKeyPath is missing", async () => {
		const { publicKeyPem } = await generateTestKeyPair("RS256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "RS256",
				kid: "v1",
				publicKey: publicKeyPem,
				previousKeys: [],
			}),
		).rejects.toThrow(/privateKey or privateKeyPath is required for RS256/i);
	});

	it("throws when asymmetric publicKey/publicKeyPath is missing", async () => {
		const { privateKeyPem } = await generateTestKeyPair("RS256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "RS256",
				kid: "v1",
				privateKey: privateKeyPem,
				previousKeys: [],
			}),
		).rejects.toThrow(/publicKey or publicKeyPath is required for RS256/i);
	});

	it("builds RS256 KeyStore with a valid previousKeys entry", async () => {
		const current = await generateTestKeyPair("RS256");
		const prev = await generateTestKeyPair("RS256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "RS256",
			kid: "v2",
			privateKey: current.privateKeyPem,
			publicKey: current.publicKeyPem,
			previousKeys: [
				{
					kid: "v1",
					publicKey: prev.publicKeyPem,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		});
		expect(keyStore.algorithm).toBe("RS256");
		const keys = await keyStore.getVerificationKeys();
		expect(keys.map((k) => k.kid)).toContain("v1");
		expect(keys.map((k) => k.kid)).toContain("v2");
	});

	it("reads private and public keys from file paths", async () => {
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("ES256");
		const privPath = join(tmpDir, "private.pem");
		const pubPath = join(tmpDir, "public.pem");
		writeFileSync(privPath, privateKeyPem);
		writeFileSync(pubPath, publicKeyPem);
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "ES256",
			kid: "fp1",
			privateKeyPath: privPath,
			publicKeyPath: pubPath,
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("ES256");
		expect(keyStore.current.kid).toBe("fp1");
	});

	it("file-path takes priority over inline PEM string when both are supplied", async () => {
		// Valid keys at the file paths; garbage strings in the inline fields.
		// If file-path wins, jose receives the real PEM and build succeeds.
		// If inline won, importPKCS8 / importSPKI would throw on the garbage.
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const privPath = join(tmpDir, "priority-private.pem");
		const pubPath = join(tmpDir, "priority-public.pem");
		writeFileSync(privPath, await exportPKCS8(privateKey));
		writeFileSync(pubPath, await exportSPKI(publicKey));
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "ES256",
			kid: "pri1",
			privateKey: "NOT A VALID PEM — should be ignored",
			privateKeyPath: privPath,
			publicKey: "ALSO INVALID PEM — should be ignored",
			publicKeyPath: pubPath,
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("ES256");
		expect(keyStore.current.kid).toBe("pri1");
	});

	it("previousKeys entry reads publicKey from file path", async () => {
		const current = await generateTestKeyPair("RS256");
		const prev = await generateTestKeyPair("RS256");
		const prevPubPath = join(tmpDir, "prev-public.pem");
		writeFileSync(prevPubPath, prev.publicKeyPem);
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "RS256",
			kid: "v3",
			privateKey: current.privateKeyPem,
			publicKey: current.publicKeyPem,
			previousKeys: [
				{
					kid: "v2",
					publicKeyPath: prevPubPath,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		});
		const keys = await keyStore.getVerificationKeys();
		expect(keys.map((k) => k.kid)).toContain("v2");
	});

	it("throws descriptive error when key file does not exist", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "ES256",
				kid: "v1",
				privateKeyPath: "/nonexistent/private.pem",
				publicKeyPath: "/nonexistent/public.pem",
				previousKeys: [],
			}),
		).rejects.toThrow(/Failed to read key file/i);
	});

	it("throws when previousKeys is not an array", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("RS256");
		await expect(
			factory.create({
				type: "local",
				algorithm: "RS256",
				kid: "v1",
				privateKey: privateKeyPem,
				publicKey: publicKeyPem,
				previousKeys: "not-an-array" as unknown,
			}),
		).rejects.toThrow(/previousKeys must be an array/i);
	});

	it("throws on invalid expiresAt for a previous key", async () => {
		const current = await generateTestKeyPair("ES256");
		const prev = await generateTestKeyPair("ES256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "ES256",
				kid: "v2",
				privateKey: current.privateKeyPem,
				publicKey: current.publicKeyPem,
				previousKeys: [
					{
						kid: "v1",
						publicKey: prev.publicKeyPem,
						expiresAt: "not-a-date",
					},
				],
			}),
		).rejects.toThrow(/Invalid expiresAt for previous key "v1"/i);
	});

	it("throws when a previousKeys entry is missing publicKey/publicKeyPath", async () => {
		const current = await generateTestKeyPair("ES256");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "ES256",
				kid: "v2",
				privateKey: current.privateKeyPem,
				publicKey: current.publicKeyPem,
				previousKeys: [
					{
						kid: "v1",
						expiresAt: "2099-12-31T00:00:00Z",
					},
				],
			}),
		).rejects.toThrow(/publicKey or publicKeyPath is required for previous key v1/i);
	});
});
