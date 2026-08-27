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
import { decodeProtectedHeader, exportPKCS8, exportSPKI, generateKeyPair, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AdapterFactoryError } from "#/adapters/AdapterFactory.mjs";
import { createKeyStoreFactory, registerBuiltinKeyStores } from "#/keys/factory.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";

async function generateTestKeyPair(alg: string) {
	const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
	return {
		privateKeyPem: await exportPKCS8(privateKey),
		publicKeyPem: await exportSPKI(publicKey),
	};
}

/**
 * HS256 test secrets must clear the 256-bit entropy floor (#282). The '.'
 * characters keep these outside the base64/base64url alphabets, so the
 * UTF-8 reading is the one that counts.
 */
const STRONG_SECRET = "test-hs256-secret.at-least-32-bytes.ok";
const STRONG_SECRET_PREVIOUS = "test-hs256-previous.at-least-32-bytes.ok";

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
			secret: STRONG_SECRET,
			previousSecrets: [],
		});
		expect(keyStore.algorithm).toBe("HS256");
		expect(keyStore.getSigningKidFallback()).toBe("v1");
	});

	it("HS256 stays selectable — it is no longer the default, but it still builds", async () => {
		// #282 flipped the shipped default to EdDSA. HS256 remains a supported
		// choice for deployments that verify in-process and publish no JWKS;
		// this test pins that it was demoted, not removed.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "HS256",
			kid: "v1",
			secret: STRONG_SECRET,
		});
		expect(keyStore.algorithm).toBe("HS256");
	});

	it("no longer silently defaults to HS256 when algorithm is absent", async () => {
		// Pre-#282 an absent `algorithm` fell back to HS256, so a deployment
		// that configured nothing at all got symmetric signing by accident.
		// The builder must now refuse rather than choose for the operator.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(factory.create({ type: "local", kid: "v1" })).rejects.toThrow(
			/algorithm.*is not configured/i,
		);
	});

	it("throws clear error when HS256 secret is missing", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({ type: "local", algorithm: "HS256", kid: "v1", previousSecrets: [] }),
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
				previousSecrets: [],
			}),
		).rejects.toThrow(/secret is required for HS256/i);
	});
});

describe("registerBuiltinKeyStores - HS256 secret entropy floor (#282)", () => {
	function build(secret: string) {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		return factory.create({
			type: "local",
			algorithm: "HS256",
			kid: "v1",
			secret,
			previousSecrets: [],
		});
	}

	it("rejects a one-character secret", async () => {
		// Pre-#282 this built a working keystore: the only check was length > 0.
		await expect(build("x")).rejects.toThrow(/at least 32 bytes/i);
	});

	it("rejects a short passphrase", async () => {
		await expect(build("test-secret")).rejects.toThrow(/at least 32 bytes/i);
	});

	it("rejects a 32-character HEX secret — 32 characters is only 16 bytes decoded", async () => {
		await expect(build("0123456789abcdef0123456789abcdef")).rejects.toThrow(/at least 32 bytes/i);
	});

	it("accepts a 64-character hex secret (32 decoded bytes)", async () => {
		const ks = await build("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
		expect(ks.algorithm).toBe("HS256");
	});

	it("accepts a 43-character base64url secret (32 decoded bytes)", async () => {
		const ks = await build("qUeYs4Xb3rTgHnKmLpVdWzCfJyBxNhQaRuEiOtSvZkA");
		expect(ks.algorithm).toBe("HS256");
	});

	it("names oauth.jwt.signingKey.local.secret and OAUTH_JWT_SECRET in the failure", async () => {
		await expect(build("x")).rejects.toThrow(/oauth\.jwt\.signingKey\.local\.secret/);
		await expect(build("x")).rejects.toThrow(/OAUTH_JWT_SECRET/);
	});

	it("does not echo the rejected secret back to the operator", async () => {
		await expect(build("hunter2-leaky")).rejects.toSatisfy(
			(err: unknown) => !(err as Error).message.includes("hunter2-leaky"),
		);
	});

	it("applies the same floor to each previousSecrets entry", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "HS256",
				kid: "v1",
				secret: STRONG_SECRET,
				previousSecrets: [{ kid: "v0", secret: "weak", expiresAt: "2099-12-31T00:00:00Z" }],
			}),
		).rejects.toThrow(/previousSecrets\[0\]\.secret.*at least 32 bytes/is);
	});
});

describe("registerBuiltinKeyStores - HS256 multi-key rotation (IH-9)", () => {
	it("factory passes previousSecrets through to createSymmetricKeyStore so an old token verifies via the new keystore", async () => {
		// Old keystore signs a token with kid "v0".
		const oldKs = createSymmetricKeyStore(STRONG_SECRET_PREVIOUS, "v0");
		const oldToken = await oldKs.sign({ claims: { sub: "user1" } });

		// Factory builds a new keystore with v0 in previousSecrets.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const newKs = await factory.create({
			type: "local",
			algorithm: "HS256",
			kid: "v1",
			secret: STRONG_SECRET,
			previousSecrets: [
				{
					kid: "v0",
					secret: STRONG_SECRET_PREVIOUS,
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
		});

		const header = decodeProtectedHeader(oldToken);
		expect(header.kid).toBe("v0");
		// Pre-fix: factory drops previousSecrets, getVerificationKey("v0") throws.
		const key = await newKs.getVerificationKey(header.kid as string);
		const { payload } = await jwtVerify(oldToken, key);
		expect(payload.sub).toBe("user1");
	});

	it("throws on invalid expiresAt for a previous secret", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "HS256",
				kid: "v1",
				secret: STRONG_SECRET,
				previousSecrets: [
					{
						kid: "v0",
						secret: STRONG_SECRET_PREVIOUS,
						expiresAt: "not-a-date",
					},
				],
			}),
		).rejects.toThrow(/previousSecrets\[0\]\.expiresAt is not a valid date/i);
	});

	it("rejects HS256 config that includes asymmetric-shaped previousKeys (defense-in-depth at factory level)", async () => {
		// Schema-level strict union already rejects this, but `factory.create()`
		// accepts `Record<string, unknown>` and bypasses the schema. The factory
		// must catch the misconfig directly so programmatic callers cannot
		// reproduce the IH-9 silent-ignore bug.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "HS256",
				kid: "v1",
				secret: STRONG_SECRET,
				previousKeys: [
					{
						kid: "v0",
						publicKey: "...pem...",
						expiresAt: "2099-12-31T00:00:00Z",
					},
				],
			}),
		).rejects.toThrow(/previousKeys is not valid for HS256/i);
	});

	it("rejects asymmetric config that includes HS256-shaped previousSecrets (mirror of the above)", async () => {
		// The asymmetric schema branch is `.passthrough()`, so a stale
		// `previousSecrets` block survives config validation. Before #282 the
		// builder silently ignored it, which is the same silent-rotation-loss
		// bug IH-9 fixed in the other direction.
		const { privateKeyPem, publicKeyPem } = await generateTestKeyPair("EdDSA");
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({
				type: "local",
				algorithm: "EdDSA",
				kid: "v1",
				privateKey: privateKeyPem,
				publicKey: publicKeyPem,
				previousSecrets: [
					{ kid: "v0", secret: STRONG_SECRET_PREVIOUS, expiresAt: "2099-12-31T00:00:00Z" },
				],
			}),
		).rejects.toThrow(/previousSecrets is not valid for EdDSA/i);
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
		expect(keyStore.getSigningKidFallback()).toBe("v1");
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
		expect(keyStore.getSigningKidFallback()).toBe("v1");
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
		expect(keyStore.getSigningKidFallback()).toBe("v1");
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
		expect(keyStore.getSigningKidFallback()).toBe("fp1");
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
		expect(keyStore.getSigningKidFallback()).toBe("pri1");
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

	it("throws when nothing at all is configured, naming the exact keys to set (#282)", async () => {
		// The critical operator-facing case: reference.conf now defaults to
		// EdDSA, so a deployment that configures no key material reaches this
		// path. It must fail at boot with instructions, never fall back to a
		// generated or default symmetric secret.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		let message = "";
		try {
			await factory.create({ type: "local", algorithm: "EdDSA", kid: "v0" });
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toMatch(/oauth\.jwt\.signingKey\.local\.privateKey/);
		expect(message).toMatch(/oauth\.jwt\.signingKey\.local\.publicKey/);
		expect(message).toMatch(/OAUTH_JWT_PRIVATE_KEY_PATH/);
		expect(message).toMatch(/OAUTH_JWT_PUBLIC_KEY_PATH/);
		// Tells the operator how to produce the material, not just that it is missing.
		expect(message).toMatch(/openssl genpkey -algorithm ed25519/i);
	});

	it("points an operator who set only OAUTH_JWT_SECRET at the HS256 opt-in (#282)", async () => {
		// Upgrade path: a 0.x deployment carrying only OAUTH_JWT_SECRET now
		// lands on the EdDSA default. The error must connect the two.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		let message = "";
		try {
			await factory.create({
				type: "local",
				algorithm: "EdDSA",
				kid: "v0",
				secret: "test-hs256-secret.at-least-32-bytes.ok",
			});
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toMatch(/OAUTH_JWT_ALGORITHM=HS256/);
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
