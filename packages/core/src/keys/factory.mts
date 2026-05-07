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
import { readFileSync } from "node:fs";
import { type AdapterFactory, createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { KeyStore, SymmetricPreviousSecret } from "./KeyStore.mjs";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "./KeyStore.mjs";

export type KeyStoreFactory = AdapterFactory<KeyStore>;

export function createKeyStoreFactory(): KeyStoreFactory {
	return createAdapterFactory<KeyStore>("KeyStore");
}

/**
 * Private helper for the "local" builder. Reads a PEM value from an inline
 * string or a file path. File path takes priority when both are supplied.
 * Returns undefined when neither is provided. Not part of the public factory API.
 */
function readKeyValue(pemString: unknown, filePath: unknown): string | undefined {
	if (typeof filePath === "string" && filePath.length > 0) {
		try {
			return readFileSync(filePath, "utf-8");
		} catch (err) {
			throw new Error(`Failed to read key file: ${filePath}`, { cause: err });
		}
	}
	if (typeof pemString === "string" && pemString.length > 0) {
		return pemString;
	}
	return undefined;
}

interface PreviousKeyEntry {
	kid: string;
	publicKey?: string;
	publicKeyPath?: string;
	expiresAt: string;
}

/**
 * Narrows config.previousKeys from unknown to a typed array.
 * Returns an empty array if the value is absent or null (explicit opt-out).
 * Throws a TypeError if the value is present but not an array (caller bug —
 * silently dropping would lose previous verification keys during rotation).
 * Throws a descriptive error for entries that are missing required fields.
 */
function narrowPreviousKeysArray(value: unknown): PreviousKeyEntry[] {
	if (value === undefined || value === null) {
		return [];
	}
	if (!Array.isArray(value)) {
		throw new TypeError("previousKeys must be an array (or undefined/null for empty)");
	}
	return value.map((entry: unknown, index: number) => {
		if (typeof entry !== "object" || entry === null) {
			throw new Error(`previousKeys[${index}] is not an object`);
		}
		const raw = entry as Record<string, unknown>;
		if (typeof raw.kid !== "string" || raw.kid.length === 0) {
			throw new Error(`previousKeys[${index}].kid must be a non-empty string`);
		}
		if (typeof raw.expiresAt !== "string" || raw.expiresAt.length === 0) {
			throw new Error(`previousKeys[${index}].expiresAt must be a non-empty string`);
		}
		return {
			kid: raw.kid,
			publicKey: typeof raw.publicKey === "string" ? raw.publicKey : undefined,
			publicKeyPath: typeof raw.publicKeyPath === "string" ? raw.publicKeyPath : undefined,
			expiresAt: raw.expiresAt,
		};
	});
}

/**
 * Narrows config.previousSecrets from unknown to a typed array of
 * SymmetricPreviousSecret. Mirrors narrowPreviousKeysArray (asymmetric)
 * but builds Date objects from ISO strings and validates the shared-secret
 * shape (kid + secret + expiresAt). HS256-only — IH-9 rotation support.
 */
function narrowPreviousSecretsArray(value: unknown): SymmetricPreviousSecret[] {
	if (value === undefined || value === null) {
		return [];
	}
	if (!Array.isArray(value)) {
		throw new TypeError("previousSecrets must be an array (or undefined/null for empty)");
	}
	return value.map((entry: unknown, index: number) => {
		if (typeof entry !== "object" || entry === null) {
			throw new Error(`previousSecrets[${index}] is not an object`);
		}
		const raw = entry as Record<string, unknown>;
		if (typeof raw.kid !== "string" || raw.kid.length === 0) {
			throw new Error(`previousSecrets[${index}].kid must be a non-empty string`);
		}
		if (typeof raw.secret !== "string" || raw.secret.length === 0) {
			throw new Error(`previousSecrets[${index}].secret must be a non-empty string`);
		}
		if (typeof raw.expiresAt !== "string" || raw.expiresAt.length === 0) {
			throw new Error(`previousSecrets[${index}].expiresAt must be a non-empty ISO string`);
		}
		const expiresAt = new Date(raw.expiresAt);
		if (Number.isNaN(expiresAt.getTime())) {
			throw new Error(`previousSecrets[${index}].expiresAt is not a valid date: ${raw.expiresAt}`);
		}
		return { kid: raw.kid, secret: raw.secret, expiresAt };
	});
}

export function registerBuiltinKeyStores(factory: KeyStoreFactory): void {
	factory.register("local", async (config) => {
		const rawAlgorithm = config.algorithm;
		const algorithm =
			typeof rawAlgorithm === "string" && rawAlgorithm.length > 0 ? rawAlgorithm : "HS256";

		if (algorithm === "HS256") {
			// IH-9 defense-in-depth: the Zod schema's strict HS256 branch
			// already rejects asymmetric-shaped `previousKeys`, but
			// `factory.create()` accepts `Record<string, unknown>` and bypasses
			// the schema — programmatic callers (tests, custom composition
			// roots) could otherwise reproduce the original silent-ignore bug.
			if (config.previousKeys !== undefined) {
				throw new Error(
					"previousKeys is not valid for HS256 — use previousSecrets (kid + secret + expiresAt). " +
						"previousKeys is the asymmetric-shaped field for RS256/ES256/EdDSA rotation.",
				);
			}
			const secret = config.secret;
			if (typeof secret !== "string" || secret.length === 0) {
				throw new Error("secret is required for HS256 algorithm");
			}
			const rawKid = config.kid;
			const kid = typeof rawKid === "string" && rawKid.length > 0 ? rawKid : "v0";
			const previousSecrets = narrowPreviousSecretsArray(config.previousSecrets);
			return createSymmetricKeyStore(secret, kid, previousSecrets);
		}

		if (algorithm === "RS256" || algorithm === "ES256" || algorithm === "EdDSA") {
			const rawKid = config.kid;
			const kid = typeof rawKid === "string" && rawKid.length > 0 ? rawKid : "v0";

			const privateKeyPem = readKeyValue(config.privateKey, config.privateKeyPath);
			if (!privateKeyPem) {
				throw new Error(`privateKey or privateKeyPath is required for ${algorithm} algorithm`);
			}

			const publicKeyPem = readKeyValue(config.publicKey, config.publicKeyPath);
			if (!publicKeyPem) {
				throw new Error(`publicKey or publicKeyPath is required for ${algorithm} algorithm`);
			}

			const previousKeys = narrowPreviousKeysArray(config.previousKeys).map((prev) => {
				const pubPem = readKeyValue(prev.publicKey, prev.publicKeyPath);
				if (!pubPem) {
					throw new Error(`publicKey or publicKeyPath is required for previous key ${prev.kid}`);
				}
				const expiresAt = new Date(prev.expiresAt);
				if (Number.isNaN(expiresAt.getTime())) {
					throw new Error(`Invalid expiresAt for previous key "${prev.kid}": ${prev.expiresAt}`);
				}
				return { kid: prev.kid, publicKeyPem: pubPem, expiresAt };
			});

			return createAsymmetricKeyStore({
				algorithm,
				kid,
				privateKeyPem,
				publicKeyPem,
				previousKeys,
			});
		}

		throw new Error(`Unsupported algorithm for local provider: ${algorithm}`);
	});
}
