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

/**
 * Thrown by {@link KeyStore.getVerificationKey} when the requested `kid` is
 * not registered in the keystore. Callers (notably the SF-1 central JWT
 * verifier) `instanceof`-check this so SIEM pipelines can distinguish
 * attacker-fabricated kids from operator-rotation expiry.
 */
export class UnknownKidError extends Error {
	override readonly name = "UnknownKidError";
	constructor(readonly kid: string) {
		super(`Unknown kid: ${kid}`);
	}
}

/**
 * Thrown by {@link KeyStore.getVerificationKey} when the requested `kid` is
 * registered but its `expiresAt` has passed. Distinct from
 * {@link UnknownKidError} so audit pipelines can page differently on
 * rotation-window expiry vs. attacker-fabricated header values.
 */
export class ExpiredKidError extends Error {
	override readonly name = "ExpiredKidError";
	constructor(
		readonly kid: string,
		readonly expiredAt: Date,
	) {
		super(`Expired kid: ${kid}`);
	}
}

export interface KeyStore {
	readonly algorithm: Algorithm;
	/**
	 * Sign claims and return a compact JWT. The KeyStore self-injects `alg`
	 * and `kid` into the protected header; callers may set only `typ`.
	 * Remote-sign adapters (KMS/HSM) perform the remote call here.
	 */
	sign(options: SignJwtOptions): Promise<string>;
	/**
	 * Returns the current signing kid as a fallback for verifying
	 * legacy/malformed tokens that lack a `kid` header. **Do not use for
	 * rotation-safe lookup** — for rotation, pass the token's own `kid` to
	 * `getVerificationKey(kid)`.
	 *
	 * **MUST be synchronous and cheap**. Remote-sign adapters (KMS/HSM)
	 * must cache the current kid locally and return it without any remote
	 * call. Never exposes private key material.
	 */
	getSigningKidFallback(): string;
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

		getSigningKidFallback(): string {
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
				throw new UnknownKidError(requestedKid);
			}
			if (prev.expiresAt <= new Date()) {
				throw new ExpiredKidError(requestedKid, prev.expiresAt);
			}
			return prev.publicKey;
		},
	};
}

export interface SymmetricPreviousSecret {
	kid: string;
	secret: string;
	expiresAt: Date;
}

/**
 * Creates an HS256 KeyStore that resolves the verification key by `kid`.
 *
 * Rotation (IH-9): when `previousSecrets` is non-empty, the keystore can
 * verify tokens signed by an older key whose `kid` is recorded in that
 * array. Issuance always uses the current `secret`/`kid`. Lookup is by
 * the JWT `kid` header — the keystore returns the matching key directly,
 * never trial-verifies across multiple keys, mirroring the asymmetric
 * `previousKeys` rotation path.
 */
export function createSymmetricKeyStore(
	secret: string,
	kid = "v0",
	previousSecrets: ReadonlyArray<SymmetricPreviousSecret> = [],
): KeyStore {
	const secretKey: KeyObject = createSecretKey(Buffer.from(secret));

	const allKids = [kid, ...previousSecrets.map((p) => p.kid)];
	const duplicates = allKids.filter((k, i) => allKids.indexOf(k) !== i);
	if (duplicates.length > 0) {
		throw new Error(`Duplicate kid values: ${[...new Set(duplicates)].join(", ")}`);
	}

	const resolvedPrevious: ReadonlyArray<{ kid: string; secretKey: KeyObject; expiresAt: Date }> =
		previousSecrets.map((p) => ({
			kid: p.kid,
			secretKey: createSecretKey(Buffer.from(p.secret)),
			expiresAt: p.expiresAt,
		}));

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

		getSigningKidFallback(): string {
			return kid;
		},

		async getVerificationKeys(): Promise<ManagedKey[]> {
			const now = new Date();
			const active = resolvedPrevious
				.filter((p) => p.expiresAt > now)
				.map((p) => ({ kid: p.kid, publicKey: p.secretKey, expiresAt: p.expiresAt }));
			return [{ kid, publicKey: secretKey }, ...active];
		},

		async getVerificationKey(requestedKid: string): Promise<KeyLike> {
			if (requestedKid === kid) {
				return secretKey;
			}
			const prev = resolvedPrevious.find((p) => p.kid === requestedKid);
			if (!prev) {
				throw new UnknownKidError(requestedKid);
			}
			if (prev.expiresAt <= new Date()) {
				throw new ExpiredKidError(requestedKid, prev.expiresAt);
			}
			return prev.secretKey;
		},
	};
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `keyStore` is a core component produced by a composition-root-local module
// (e.g. `keyStoreModule` in A2-γ §3.8 standalone template). Modules that
// need the KeyStore to sign or verify tokens declare `requires: ["keyStore"]`
// and receive the instance through the typed DI graph.
//
// Per A2-γ §3.2.3 / §3.2.2 / §3.2.1: oauthSessionModule, oauthAuthorization-
// Module, and oauthModule all require keyStore in their defineModule manifests.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly keyStore: KeyStore;
	}
}
