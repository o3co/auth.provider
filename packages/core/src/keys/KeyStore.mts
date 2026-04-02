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
import { importPKCS8, importSPKI } from "jose";

export type KeyLike = CryptoKey | KeyObject | Uint8Array;

export interface ManagedKey {
	kid: string;
	publicKey: KeyLike;
	expiresAt?: Date;
}

export interface KeyStore {
	readonly algorithm: string;
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
	algorithm: string;
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
