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
