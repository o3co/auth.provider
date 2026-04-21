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
import { importPKCS8, importSPKI, SignJWT } from "jose";

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

/**
 * Input to `KeyStore.sign()`. The KeyStore self-injects `alg` and `kid` into
 * the protected header; callers may only set `typ`. This keeps adapter
 * contracts stable under alg / kid rotation and remote-sign (KMS/HSM) backends.
 */
export interface SignJwtOptions {
	claims: JWTPayload;
	header?: { typ?: string };
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
	/**
	 * Sign claims and return a compact JWT. The KeyStore self-injects `alg`
	 * and `kid` into the protected header; callers may set only `typ`.
	 * Remote-sign adapters (KMS/HSM) perform the remote call here.
	 */
	sign(options: SignJwtOptions): Promise<string>;
	/**
	 * Current signing kid. Intended as a fallback for verifying
	 * legacy/malformed tokens missing a `kid` header. **Do not use for
	 * rotation-safe lookup** — for rotation, pass the token's own `kid` to
	 * `getVerificationKey(kid)`. Cheap, sync, does not expose any private key.
	 */
	getCurrentKid(): string;
	/** Active verification keys for JWKS endpoint. Remote adapters may fetch + cache. */
	getVerificationKeys(): Promise<ManagedKey[]>;
	/** Specific kid's public key. Throws on unknown or expired kid. */
	getVerificationKey(kid: string): Promise<KeyLike>;
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

		async sign({ claims, header }: SignJwtOptions): Promise<string> {
			return await new SignJWT(claims)
				.setProtectedHeader({
					alg: algorithm,
					kid,
					...(header?.typ ? { typ: header.typ } : {}),
				})
				.sign(privateKey);
		},

		getCurrentKid(): string {
			return kid;
		},

		async getVerificationKeys(): Promise<ManagedKey[]> {
			const now = new Date();
			const active = resolvedPrevious.filter((k) => k.expiresAt > now);
			return [{ kid, publicKey }, ...active];
		},

		async getVerificationKey(requestedKid: string): Promise<KeyLike> {
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

		async sign({ claims, header }: SignJwtOptions): Promise<string> {
			return await new SignJWT(claims)
				.setProtectedHeader({
					alg: "HS256",
					kid,
					...(header?.typ ? { typ: header.typ } : {}),
				})
				.sign(secretKey);
		},

		getCurrentKid(): string {
			return kid;
		},

		async getVerificationKeys(): Promise<ManagedKey[]> {
			return [{ kid, publicKey: secretKey }];
		},

		async getVerificationKey(requestedKid: string): Promise<KeyLike> {
			if (requestedKid !== kid) {
				throw new Error(`Unknown kid: ${requestedKid}`);
			}
			return secretKey;
		},
	};
}
