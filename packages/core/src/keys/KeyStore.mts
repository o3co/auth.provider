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
import { createSecretKey, type KeyObject, type webcrypto } from "node:crypto";
import { importPKCS8, importSPKI, SignJWT } from "jose";
import { assertWellFormedKids } from "./kid.mjs";

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

// `webcrypto.CryptoKey` (not the bare global `CryptoKey`): the global type is
// only declared by @types/node >= 24, but this package supports Node >= 22 (see
// `engines`). Both refer to the same Web Crypto key shape, so consumers are
// unaffected; do NOT "simplify" this back to `CryptoKey` — it breaks typecheck
// on the minimum supported @types/node.
export type KeyLike = webcrypto.CryptoKey | KeyObject | Uint8Array;

export interface ManagedKey {
	kid: string;
	publicKey: KeyLike;
	expiresAt?: Date;
}

export type Algorithm = "HS256" | "RS256" | "ES256" | "EdDSA";

/**
 * A `kid` as text for an error message, whatever a caller hands over: a kid
 * is the client's header value, and a finding error that could not be built
 * from it would be thrown as a TypeError instead — which the verifier would
 * read as the keystore failing to answer. Long values are cut.
 */
const describeKid = (kid: unknown): string =>
	typeof kid !== "string" ? `(${typeof kid})` : kid.length > 64 ? `${kid.slice(0, 64)}...` : kid;

/**
 * Thrown by {@link KeyStore.getVerificationKey} when the requested `kid` is
 * not registered. The central JWT verifier recognises it by class, or by this
 * `name` when a composition holds two copies of the package, so SIEM can tell
 * fabricated kids from rotation expiry and from a keystore that cannot
 * answer. Building one never throws, whatever `kid` is.
 */
export class UnknownKidError extends Error {
	override readonly name = "UnknownKidError";
	constructor(readonly kid: string) {
		super(`Unknown kid: ${describeKid(kid)}`);
	}
}

/**
 * Thrown by {@link KeyStore.getVerificationKey} when the requested `kid` is
 * registered but its `expiresAt` has passed. Distinct from
 * {@link UnknownKidError} so audit pipelines can page differently on
 * rotation-window expiry vs. attacker-fabricated header values. Recognised
 * by class or by this `name`, like {@link UnknownKidError}, and building one
 * never throws.
 */
export class ExpiredKidError extends Error {
	override readonly name = "ExpiredKidError";
	constructor(
		readonly kid: string,
		readonly expiredAt: Date,
	) {
		super(`Expired kid: ${describeKid(kid)}`);
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
	 * The current signing kid, the fallback for verifying tokens that lack a
	 * `kid` header. Not for rotation-safe lookup: pass the token's own `kid`
	 * to `getVerificationKey`. MUST be synchronous and cheap: remote-sign
	 * adapters (KMS/HSM) cache the current kid locally. A throw here reads as
	 * the keystore being unable to answer (`verification_key_unavailable`).
	 */
	getSigningKidFallback(): string;
	/** Active verification keys for JWKS endpoint. Remote adapters may fetch + cache. */
	getVerificationKeys(): Promise<ManagedKey[]>;
	/**
	 * The public key for `kid`. The contract `verifyJwt` relies on:
	 *
	 * - A `kid` this keystore does not hold MUST throw {@link UnknownKidError},
	 *   a retired one {@link ExpiredKidError}: findings about the token
	 *   (`kid_unknown` / `kid_expired`), the client's fault.
	 * - Any other throw means the keystore cannot answer
	 *   (`verification_key_unavailable`, answered `503` and logged as an
	 *   outage), so throwing anything else for a kid that merely looks wrong
	 *   turns the client's token into the server's outage.
	 * - `kid` is untrusted input read before the signature is checked: at most
	 *   `MAX_KID_LENGTH` characters with no control character, otherwise
	 *   anything (`/`, `?`, `..`). An adapter that looks keys up remotely (KMS,
	 *   HSM, JWKS endpoint) MUST check it against its own key naming before it
	 *   reaches that system, never interpolate it unchecked into a URL, path or
	 *   query, and answer a failed check with {@link UnknownKidError}.
	 */
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
	// A kid verifyJwt would refuse makes every token signed under it fail.
	assertWellFormedKids("createAsymmetricKeyStore", [
		["kid", kid],
		...previousKeys.map((prev, i) => [`previousKeys[${i}].kid`, prev.kid] as const),
	]);

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
 * Does not enforce the secret entropy floor: that belongs at the config
 * boundary (the `"local"` builder of `registerBuiltinKeyStores`, and the
 * session store's section schema for `session-store.secret`). A composition
 * root passing an operator-supplied secret here applies `assertSecretEntropy`
 * itself.
 *
 * Rotation: `previousSecrets` verify tokens whose `kid` names an older key;
 * issuance always uses the current `secret`/`kid`. Lookup is by `kid`, never
 * trial verification across keys, as with the asymmetric `previousKeys`.
 */
export function createSymmetricKeyStore(
	secret: string,
	kid = "v0",
	previousSecrets: ReadonlyArray<SymmetricPreviousSecret> = [],
): KeyStore {
	// A kid verifyJwt would refuse makes every token signed under it fail.
	assertWellFormedKids("createSymmetricKeyStore", [
		["kid", kid],
		...previousSecrets.map((prev, i) => [`previousSecrets[${i}].kid`, prev.kid] as const),
	]);
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
// ComponentMap slot declaration
//
// `keyStore` is a core component provided by a composition-root module (e.g.
// the standalone template's `keyStoreModule`). Modules that sign or verify
// tokens declare `requires: ["keyStore"]` and receive it through the typed DI
// graph.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly keyStore: KeyStore;
	}
}
