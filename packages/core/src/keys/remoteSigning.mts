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

import { importSPKI } from "jose";
import {
	ExpiredKidError,
	type KeyLike,
	type KeyStore,
	type ManagedKey,
	type SignJwtOptions,
	UnknownKidError,
} from "./KeyStore.mjs";

/**
 * The one thing a KMS, an HSM or a Vault-style provider has to do (#303):
 * produce a signature over bytes it is handed, using a key it never surrenders.
 *
 * This is the whole seam. Everything else a `KeyStore` owes — building the
 * protected header, base64url encoding, assembling the compact JWT, rotation
 * bookkeeping, publishing JWKS — is the same regardless of where the private
 * key lives, and is done by {@link createRemoteSigningKeyStore} so an
 * integrator does not reimplement it per vendor and get it subtly wrong.
 *
 * ## The signature format, stated because it is the trap
 *
 * `signature` MUST be in **JWS form** (RFC 7515 §3.3, RFC 7518 §3.4):
 *
 * - `RS256` — PKCS#1 v1.5, which is what every provider returns for RSASSA.
 * - `EdDSA` — the raw 64-byte Ed25519 signature.
 * - `ES256` — the **raw `R || S` concatenation, 64 bytes**, *not* the DER
 *   `SEQUENCE` that AWS KMS, PKCS#11 and OpenSSL hand back. This is the one
 *   that bites: DER is accepted by nothing that verifies JWS, and the failure
 *   is a signature mismatch at the relying party rather than an error at the
 *   signer. Use {@link derToJoseEcdsaSignature} on the way out.
 *
 * The store cannot detect the wrong form for you — a DER blob is bytes like
 * any other — so it verifies its own output once at construction
 * (`verifyOnConstruction`, default on). A misconfigured signer then fails at
 * boot rather than issuing tokens nothing can verify.
 */
export interface RemoteSigner {
	/**
	 * Sign `data` with the private key named `kid` and return the signature in
	 * JWS form. Called once per token issued, so a provider round-trip here is
	 * on the token endpoint's hot path.
	 */
	sign(kid: string, data: Uint8Array): Promise<Uint8Array>;
}

/** A key this store publishes but no longer signs with. */
export interface RemoteSigningPreviousKey {
	readonly kid: string;
	/** SPKI PEM. Public material only — that is the point of this store. */
	readonly publicKeyPem: string;
	readonly expiresAt: Date;
}

export interface RemoteSigningKeyStoreOptions {
	/** `HS256` is deliberately absent — see the module comment. */
	readonly algorithm: "RS256" | "ES256" | "EdDSA";
	readonly kid: string;
	readonly signer: RemoteSigner;
	/** SPKI PEM for `kid`. Public material only. */
	readonly publicKeyPem: string;
	readonly previousKeys?: readonly RemoteSigningPreviousKey[];
	/**
	 * Verify one self-signed token at construction, so a signer returning the
	 * wrong signature form fails boot instead of issuing unverifiable tokens.
	 * Costs one provider call per process start. Default `true`; turn it off
	 * only where a boot-time provider call is itself the problem.
	 */
	readonly verifyOnConstruction?: boolean;
}

const base64url = (input: Uint8Array | string): string =>
	Buffer.from(typeof input === "string" ? new TextEncoder().encode(input) : input).toString(
		"base64url",
	);

/**
 * Convert a DER-encoded ECDSA signature to the raw `R || S` form JWS requires.
 *
 * AWS KMS, PKCS#11 and OpenSSL all return DER; JWS wants the concatenation.
 * Exported because every integrator building an `ES256` {@link RemoteSigner}
 * needs it, and the alternative is each of them writing this parser from the
 * ASN.1 spec — which is how one of them gets the leading-zero trimming wrong
 * and produces signatures that verify only sometimes.
 *
 * `size` is the field size in bytes (32 for P-256), so each half is
 * left-padded to exactly that width.
 */
export function derToJoseEcdsaSignature(der: Uint8Array, size = 32): Uint8Array {
	if (der[0] !== 0x30) {
		throw new Error("derToJoseEcdsaSignature: not a DER SEQUENCE (expected 0x30)");
	}
	const lengthByte = der[1];
	if (lengthByte === undefined) {
		throw new Error("derToJoseEcdsaSignature: truncated SEQUENCE header");
	}
	// DER forbids the indefinite form (0x80) — BER allows it, DER does not, and
	// treating it as a zero-byte long form would silently misparse rather than
	// refuse. Every refusal in this parser exists for that reason: a lenient
	// byte reader hands back a plausible signature that verifies nowhere, which
	// is the far-from-the-cause failure this whole module is built to avoid.
	if (lengthByte === 0x80) {
		throw new Error("derToJoseEcdsaSignature: indefinite-length SEQUENCE is not valid DER");
	}
	let contentLength: number;
	let offset: number;
	if (lengthByte < 0x80) {
		contentLength = lengthByte;
		offset = 2;
	} else {
		const lengthOfLength = lengthByte & 0x7f;
		offset = 2 + lengthOfLength;
		if (der.length < offset) {
			throw new Error("derToJoseEcdsaSignature: truncated long-form SEQUENCE length");
		}
		contentLength = 0;
		for (let i = 0; i < lengthOfLength; i += 1) {
			contentLength = contentLength * 256 + (der[2 + i] ?? 0);
		}
	}
	const contentEnd = offset + contentLength;
	if (der.length < contentEnd) {
		throw new Error("derToJoseEcdsaSignature: SEQUENCE length exceeds the bytes provided");
	}

	const readInteger = (): Uint8Array => {
		if (der[offset] !== 0x02) {
			throw new Error("derToJoseEcdsaSignature: expected an INTEGER (0x02)");
		}
		const length = der[offset + 1];
		if (length === undefined) {
			throw new Error("derToJoseEcdsaSignature: truncated INTEGER");
		}
		const start = offset + 2;
		offset = start + length;
		let value = der.subarray(start, offset);
		// DER prefixes a 0x00 when the high bit would make the value negative;
		// JWS carries fixed-width unsigned halves, so it comes back off.
		while (value.length > size && value[0] === 0x00) value = value.subarray(1);
		if (value.length > size) {
			throw new Error("derToJoseEcdsaSignature: INTEGER wider than the field size");
		}
		const padded = new Uint8Array(size);
		padded.set(value, size - value.length);
		return padded;
	};

	const r = readInteger();
	const s = readInteger();
	// Extra bytes mean this is not the two-INTEGER SEQUENCE an ECDSA signature
	// is. Accepting them would return a well-formed-looking JWS half-pair that
	// never verifies — the signer reports success and every relying party
	// rejects the token, far from the cause.
	if (offset !== contentEnd) {
		throw new Error(
			"derToJoseEcdsaSignature: trailing bytes after R and S — not an ECDSA signature",
		);
	}
	const out = new Uint8Array(size * 2);
	out.set(r, 0);
	out.set(s, size);
	return out;
}

/**
 * A {@link KeyStore} whose private key never enters this process (#303).
 *
 * ## Why this is vendor-neutral
 *
 * The issue asks for "the port + one reference, e.g. AWS KMS". Shipping an AWS
 * SDK dependency in `core` would put a vendor in the dependency closure of
 * every deployment, including the ones signing with a PKCS#11 token or a
 * Vault transit key — the same reason the delivery port (#302) is specified as
 * "no bundled vendor". So the reference is the shape, not the vendor: an
 * integrator supplies `sign(kid, data)` and this does the rest.
 *
 * ## Why `HS256` is not accepted
 *
 * A shared secret has no public half, so "the key never leaves the boundary"
 * cannot be true of it — every verifier needs the same bytes the signer has.
 * Offering it here would let a deployment believe it had moved key material
 * out of reach when it had not. HS256 stays on `createSymmetricKeyStore`,
 * where the trade-off is visible.
 *
 * ## Rotation
 *
 * Identical to `createAsymmetricKeyStore`: `previousKeys` keep verifying (and
 * keep appearing in JWKS) until `expiresAt`, after which `getVerificationKey`
 * throws {@link ExpiredKidError} rather than {@link UnknownKidError}, so the
 * two stay distinguishable to a SIEM.
 */
export async function createRemoteSigningKeyStore(
	options: RemoteSigningKeyStoreOptions,
): Promise<KeyStore> {
	const {
		algorithm,
		kid,
		signer,
		publicKeyPem,
		previousKeys = [],
		verifyOnConstruction = true,
	} = options;

	const allKids = [kid, ...previousKeys.map((k) => k.kid)];
	const duplicates = allKids.filter((k, i) => allKids.indexOf(k) !== i);
	if (duplicates.length > 0) {
		throw new Error(
			`createRemoteSigningKeyStore: duplicate kid values: ${[...new Set(duplicates)].join(", ")}`,
		);
	}

	const publicKey = (await importSPKI(publicKeyPem, algorithm)) as KeyLike;
	const resolvedPrevious = await Promise.all(
		previousKeys.map(async (prev) => ({
			kid: prev.kid,
			publicKey: (await importSPKI(prev.publicKeyPem, algorithm)) as KeyLike,
			expiresAt: prev.expiresAt,
		})),
	);

	const store: KeyStore = {
		algorithm,

		async sign({ claims, header }: SignJwtOptions): Promise<string> {
			// The protected header is built here, not by the signer: `alg` and
			// `kid` are the store's to choose, and a signer that could set them
			// could sign under a header the deployment never configured.
			const protectedHeader = {
				alg: algorithm,
				kid,
				...(header?.typ ? { typ: header.typ } : {}),
			};
			const signingInput = `${base64url(JSON.stringify(protectedHeader))}.${base64url(
				JSON.stringify(claims),
			)}`;
			const signature = await signer.sign(kid, new TextEncoder().encode(signingInput));
			return `${signingInput}.${base64url(signature)}`;
		},

		getSigningKidFallback(): string {
			// Local, per the port's MUST: this runs on the verify path for every
			// token arriving without a `kid`, and a provider round-trip there
			// would put the KMS on the critical path of every such request.
			return kid;
		},

		async getVerificationKeys(): Promise<ManagedKey[]> {
			const now = Date.now();
			return [
				{ kid, publicKey },
				...resolvedPrevious
					.filter((p) => p.expiresAt.getTime() > now)
					.map((p) => ({ kid: p.kid, publicKey: p.publicKey, expiresAt: p.expiresAt })),
			];
		},

		async getVerificationKey(requestedKid: string): Promise<KeyLike> {
			if (requestedKid === kid) return publicKey;
			const previous = resolvedPrevious.find((p) => p.kid === requestedKid);
			if (previous === undefined) throw new UnknownKidError(requestedKid);
			if (previous.expiresAt.getTime() <= Date.now()) {
				throw new ExpiredKidError(requestedKid, previous.expiresAt);
			}
			return previous.publicKey;
		},
	};

	if (verifyOnConstruction) {
		// One self-signed token, verified with the public half this store
		// publishes. A signer returning DER instead of R||S, or signing with a
		// key that does not match `publicKeyPem`, fails here — at boot, with a
		// message naming the cause — rather than at every relying party.
		const { jwtVerify } = await import("jose");
		const probe = await store.sign({ claims: { sub: "__keystore_self_check__" } });
		try {
			await jwtVerify(probe, publicKey as never);
		} catch (cause) {
			// The form hint is algorithm-specific. `ES256` is the one that
			// actually bites — providers return DER there and nowhere else — so
			// pointing an RS256 or EdDSA operator at a DER conversion sends them
			// to look at the one thing that cannot be their problem.
			const formHint =
				algorithm === "ES256"
					? "the signature is not in JWS form (ES256 providers return DER, not the raw " +
						"R || S concatenation — see derToJoseEcdsaSignature)"
					: `the signature is not in JWS form (${algorithm} expects the raw signature ` +
						"bytes, unwrapped)";
			throw new Error(
				"createRemoteSigningKeyStore: the signer's output does not verify against " +
					`publicKeyPem for kid "${kid}". Two causes account for almost all of these: ` +
					`${formHint}, or the signer is using a different key than the public half ` +
					"configured here.",
				{ cause },
			);
		}
	}

	return store;
}
