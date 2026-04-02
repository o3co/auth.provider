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
import { type KeyObject, createSecretKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { importPKCS8, importSPKI } from "jose";

export type KeyLike = CryptoKey | KeyObject | Uint8Array;

export interface ManagedKey {
	kid: string;
	publicKey: KeyLike;
	expiresAt?: Date;
}

export type Algorithm = "HS256" | "RS256" | "ES256" | "EdDSA";

export interface KeyStore {
	readonly algorithm: Algorithm;
	readonly current: {
		readonly kid: string;
		readonly privateKey: KeyLike;
		readonly publicKey: KeyLike;
	};
	readonly previous: readonly ManagedKey[];
	getSigningKey(): { kid: string; privateKey: KeyLike };
	getVerificationKeys(): ManagedKey[];
	getVerificationKey(kid: string): KeyLike;
}

export interface AsymmetricKeyStoreOptions {
	algorithm: "RS256" | "ES256" | "EdDSA";
	kid: string;
	privateKeyPem: string;
	publicKeyPem: string;
	previousKeys?: Array<{
		kid: string;
		publicKeyPem: string;
		expiresAt: Date;
	}>;
}

export async function createAsymmetricKeyStore(options: AsymmetricKeyStoreOptions): Promise<KeyStore> {
	const { algorithm, kid, privateKeyPem, publicKeyPem, previousKeys = [] } = options;

	// Validate kid uniqueness
	const allKids = [kid, ...previousKeys.map((k) => k.kid)];
	const duplicates = allKids.filter((k, i) => allKids.indexOf(k) !== i);
	if (duplicates.length > 0) {
		throw new Error(`Duplicate kid values: ${[...new Set(duplicates)].join(", ")}`);
	}

	const privateKey = await importPKCS8(privateKeyPem, algorithm);
	const publicKey = await importSPKI(publicKeyPem, algorithm);

	// Import all previous public keys upfront
	const resolvedPrevious: Array<ManagedKey & { expiresAt: Date }> = await Promise.all(
		previousKeys.map(async (prev) => ({
			kid: prev.kid,
			publicKey: await importSPKI(prev.publicKeyPem, algorithm) as KeyLike,
			expiresAt: prev.expiresAt,
		})),
	);

	return {
		algorithm,
		current: { kid, privateKey, publicKey },
		previous: resolvedPrevious,

		getSigningKey() {
			return { kid, privateKey };
		},

		getVerificationKeys(): ManagedKey[] {
			const now = new Date();
			const active = resolvedPrevious.filter((k) => k.expiresAt > now);
			return [{ kid, publicKey }, ...active];
		},

		getVerificationKey(requestedKid: string): KeyLike {
			if (requestedKid === kid) {
				return publicKey;
			}
			const prev = resolvedPrevious.find((k) => k.kid === requestedKid);
			if (!prev) {
				throw new Error(`Unknown kid: ${requestedKid}`);
			}
			if (prev.expiresAt <= new Date()) {
				throw new Error(`Expired kid: ${requestedKid}`);
			}
			return prev.publicKey;
		},
	};
}

export interface JwtConfig {
	algorithm: "HS256" | "RS256" | "ES256" | "EdDSA";
	secret?: string;
	kid: string;
	issuer?: string;
	privateKey?: string;
	privateKeyPath?: string;
	publicKey?: string;
	publicKeyPath?: string;
	previousKeys: Array<{
		kid: string;
		publicKey?: string;
		publicKeyPath?: string;
		expiresAt: string;
	}>;
}

function readKeyValue(pemString?: string, filePath?: string): string | undefined {
	if (filePath) {
		try {
			return readFileSync(filePath, "utf-8");
		} catch (err) {
			throw new Error(`Failed to read key file: ${filePath}`, { cause: err });
		}
	}
	return pemString;
}

export async function createKeyStoreFromConfig(config: JwtConfig): Promise<KeyStore> {
	if (config.algorithm === "HS256") {
		if (!config.secret) {
			throw new Error("secret is required for HS256 algorithm");
		}
		return createSymmetricKeyStore(config.secret, config.kid);
	}

	// Asymmetric algorithms: RS256, ES256, EdDSA
	const privateKeyPem = readKeyValue(config.privateKey, config.privateKeyPath);
	if (!privateKeyPem) {
		throw new Error(`privateKey or privateKeyPath is required for ${config.algorithm} algorithm`);
	}

	const publicKeyPem = readKeyValue(config.publicKey, config.publicKeyPath);
	if (!publicKeyPem) {
		throw new Error(`publicKey or publicKeyPath is required for ${config.algorithm} algorithm`);
	}

	const previousKeys = config.previousKeys.map((prev) => {
		const pubPem = readKeyValue(prev.publicKey, prev.publicKeyPath);
		if (!pubPem) {
			throw new Error(`publicKey or publicKeyPath is required for previous key ${prev.kid}`);
		}
		const expiresAt = new Date(prev.expiresAt);
		if (Number.isNaN(expiresAt.getTime())) {
			throw new Error(`Invalid expiresAt for previous key "${prev.kid}": ${prev.expiresAt}`);
		}
		return {
			kid: prev.kid,
			publicKeyPem: pubPem,
			expiresAt,
		};
	});

	return createAsymmetricKeyStore({
		algorithm: config.algorithm,
		kid: config.kid,
		privateKeyPem,
		publicKeyPem,
		previousKeys,
	});
}

export function createSymmetricKeyStore(secret: string, kid = "v0"): KeyStore {
	const secretKey: KeyObject = createSecretKey(Buffer.from(secret));

	return {
		algorithm: "HS256",
		current: {
			kid,
			privateKey: secretKey,
			publicKey: secretKey,
		},
		previous: [],

		getSigningKey() {
			return { kid, privateKey: secretKey };
		},

		getVerificationKeys(): ManagedKey[] {
			return [{ kid, publicKey: secretKey }];
		},

		getVerificationKey(requestedKid: string): KeyLike {
			if (requestedKid !== kid) {
				throw new Error(`Unknown kid: ${requestedKid}`);
			}
			return secretKey;
		},
	};
}
