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
import { createSecretKey, type KeyObject } from "node:crypto";
import { importPKCS8, importSPKI } from "jose";

/**
 * JWT claims per RFC 7519. Standard claims are typed; custom claims are
 * allowed via index signature. Defined here to keep the KeyStore interface
 * jose-independent — implementations may use jose, node-jose, fast-jwt, or
 * direct KMS SDK calls.
 */
export interface JWTPayload {
	iss?: string;
	sub?: string;
	aud?: string | string[];
	jti?: string;
	nbf?: number;
	exp?: number;
	iat?: number;
	[propName: string]: unknown;
}

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

export async function createAsymmetricKeyStore(
	options: AsymmetricKeyStoreOptions,
): Promise<KeyStore> {
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
			publicKey: (await importSPKI(prev.publicKeyPem, algorithm)) as KeyLike,
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
