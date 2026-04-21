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

/**
 * Internal-only test fixtures for KeyStore. Not re-exported from the package
 * root, not shipped in `dist`. External KMS/HSM adapter authors should
 * implement the `KeyStore` interface directly per its TSDoc contract.
 */
import type { Algorithm, KeyLike, KeyStore, ManagedKey, SignJwtOptions } from "../KeyStore.mjs";

export interface TestKeyStoreOptions {
	algorithm: Algorithm;
	kid: string;
	signer: (options: SignJwtOptions) => Promise<string>;
	verificationKeys: ReadonlyMap<string, KeyLike>;
	expirations?: ReadonlyMap<string, Date>;
}

export function createTestKeyStore(options: TestKeyStoreOptions): KeyStore {
	const { algorithm, kid, signer, verificationKeys, expirations } = options;
	return {
		algorithm,
		async sign(opts) {
			return signer(opts);
		},
		getSigningKidFallback() {
			return kid;
		},
		async getVerificationKey(requestedKid) {
			const key = verificationKeys.get(requestedKid);
			if (!key) throw new Error(`Unknown kid: ${requestedKid}`);
			const exp = expirations?.get(requestedKid);
			if (exp && exp <= new Date()) throw new Error(`Expired kid: ${requestedKid}`);
			return key;
		},
		async getVerificationKeys(): Promise<ManagedKey[]> {
			const now = new Date();
			const result: ManagedKey[] = [];
			for (const [k, publicKey] of verificationKeys.entries()) {
				const exp = expirations?.get(k);
				if (exp && exp <= now) continue;
				result.push(exp ? { kid: k, publicKey, expiresAt: exp } : { kid: k, publicKey });
			}
			return result;
		},
	};
}
