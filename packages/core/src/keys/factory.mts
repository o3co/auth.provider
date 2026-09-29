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
import { assertSecretEntropy } from "./secretEntropy.mjs";

export type KeyStoreFactory = AdapterFactory<KeyStore>;

/**
 * The algorithm this library defaults to, and the one `reference.conf` ships.
 * Asymmetric so a relying party can verify from the published JWKS without
 * holding a key that can also MINT tokens. EdDSA (Ed25519) over RS256: every
 * layer here supports it, its keys and signatures are the smallest, and it
 * has no parameter (key size, padding) an operator can get quietly wrong.
 */
export const DEFAULT_SIGNING_ALGORITHM = "EdDSA";

const SUPPORTED_ALGORITHMS = ["HS256", "RS256", "ES256", "EdDSA"] as const;

/** Env vars `reference.conf` binds the asymmetric key material to. */
const ASYMMETRIC_KEY_HELP =
	"Set BOTH of:\n" +
	"  oauth.jwt.signingKey.local.privateKeyPath  (env OAUTH_JWT_PRIVATE_KEY_PATH)\n" +
	"  oauth.jwt.signingKey.local.publicKeyPath   (env OAUTH_JWT_PUBLIC_KEY_PATH)\n" +
	"or their inline-PEM equivalents oauth.jwt.signingKey.local.privateKey /\n" +
	".publicKey (env OAUTH_JWT_PRIVATE_KEY / OAUTH_JWT_PUBLIC_KEY).\n" +
	"Generate an Ed25519 pair with:\n" +
	"  openssl genpkey -algorithm ed25519 -out jwt-private.pem\n" +
	"  openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem";

/**
 * The boot failure for an asymmetric algorithm with no key material. It names
 * the exact keys and command, and when a `secret` is present (an HS256 config
 * carried forward) explains that too, rather than a baffling "privateKey is
 * required" against a config that visibly has a key.
 */
function describeMissingAsymmetricMaterial(
	algorithm: string,
	missing: "privateKey" | "publicKey",
	hasSecret: boolean,
): string {
	const head =
		missing === "privateKey"
			? `${missing} or ${missing}Path is required for ${algorithm} algorithm — no signing key is configured.`
			: `${missing} or ${missing}Path is required for ${algorithm} algorithm.`;
	const hs256Note = hasSecret
		? "\n\noauth.jwt.signingKey.local.secret is set, but a shared secret cannot sign " +
			`${algorithm}. To keep symmetric signing instead, set ` +
			'oauth.jwt.signingKey.local.algorithm = "HS256" (env OAUTH_JWT_ALGORITHM=HS256). ' +
			"Note that HS256 publishes no JWKS, so every relying party must be handed the " +
			"shared secret — which also lets it mint tokens."
		: "";
	return `${head}\n\n${ASYMMETRIC_KEY_HELP}${hs256Note}`;
}

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
 * Narrows config.previousSecrets to SymmetricPreviousSecret[] (HS256
 * rotation). Mirrors narrowPreviousKeysArray, but builds Date objects from ISO
 * strings and validates kid + secret + expiresAt.
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
		// A retired secret is still a live verification key for the whole
		// overlap window, so it carries exactly the forgery risk the current
		// secret does and clears exactly the same floor.
		assertSecretEntropy(raw.secret, {
			configKey: `oauth.jwt.signingKey.local.previousSecrets[${index}].secret`,
			envVar: "OAUTH_JWT_SECRET",
		});
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

/**
 * Registers the `local` builder, the in-config path.
 *
 * There is deliberately no `remote` builder: `createRemoteSigningKeyStore`
 * needs a `RemoteSigner`, a function calling AWS KMS, a PKCS#11 token or a
 * Vault transit key, and HOCON has no spelling for a function. A deployment
 * that signs remotely builds the store in its composition root and supplies
 * it as the `keyStore` component. A `remote` config type would mean bundling
 * a vendor SDK into core, or a plugin lookup that turns a string back into
 * the callback the composition root already had.
 */
export function registerBuiltinKeyStores(factory: KeyStoreFactory): void {
	factory.register("local", async (config) => {
		const rawAlgorithm = config.algorithm;
		// No fallback: an absent `algorithm` must not silently become HS256,
		// quietly weaker than the operator believes. `reference.conf` always
		// supplies it, so only a programmatic caller reaches this.
		if (typeof rawAlgorithm !== "string" || rawAlgorithm.length === 0) {
			throw new Error(
				"oauth.jwt.signingKey.local.algorithm is not configured (env OAUTH_JWT_ALGORITHM). " +
					`Supported values: ${SUPPORTED_ALGORITHMS.join(", ")}. ` +
					`The shipped default is "${DEFAULT_SIGNING_ALGORITHM}"; there is no implicit fallback.`,
			);
		}
		const algorithm = rawAlgorithm;

		if (algorithm === "HS256") {
			// Defense in depth: the schema's HS256 branch rejects `previousKeys`,
			// but `factory.create()` bypasses the schema, and a programmatic
			// caller's `previousKeys` would otherwise be silently ignored.
			if (config.previousKeys !== undefined) {
				throw new Error(
					"previousKeys is not valid for HS256 — use previousSecrets (kid + secret + expiresAt). " +
						"previousKeys is the asymmetric-shaped field for RS256/ES256/EdDSA rotation.",
				);
			}
			const secret = config.secret;
			if (typeof secret !== "string" || secret.length === 0) {
				throw new Error(
					"secret is required for HS256 algorithm. Set " +
						"oauth.jwt.signingKey.local.secret (env OAUTH_JWT_SECRET) to at least " +
						"32 bytes of random material — `openssl rand -hex 32`.",
				);
			}
			// Anyone who guesses an HS256 secret can MINT tokens for any subject,
			// so it must clear the entropy floor, not merely be non-empty.
			assertSecretEntropy(secret, {
				configKey: "oauth.jwt.signingKey.local.secret",
				envVar: "OAUTH_JWT_SECRET",
			});
			const rawKid = config.kid;
			const kid = typeof rawKid === "string" && rawKid.length > 0 ? rawKid : "v0";
			const previousSecrets = narrowPreviousSecretsArray(config.previousSecrets);
			return createSymmetricKeyStore(secret, kid, previousSecrets);
		}

		if (algorithm === "RS256" || algorithm === "ES256" || algorithm === "EdDSA") {
			// Mirror of the HS256 guard: the asymmetric schema branch is
			// `.passthrough()`, so a `previousSecrets` block left over from an
			// HS256 config would otherwise be silently dropped, losing rotation.
			if (config.previousSecrets !== undefined) {
				throw new Error(
					`previousSecrets is not valid for ${algorithm} — use previousKeys ` +
						"(kid + publicKey/publicKeyPath + expiresAt). previousSecrets is the " +
						"symmetric-shaped field for HS256 rotation.",
				);
			}
			const rawKid = config.kid;
			const kid = typeof rawKid === "string" && rawKid.length > 0 ? rawKid : "v0";
			const hasSecret = typeof config.secret === "string" && config.secret.length > 0;

			const privateKeyPem = readKeyValue(config.privateKey, config.privateKeyPath);
			if (!privateKeyPem) {
				throw new Error(describeMissingAsymmetricMaterial(algorithm, "privateKey", hasSecret));
			}

			const publicKeyPem = readKeyValue(config.publicKey, config.publicKeyPath);
			if (!publicKeyPem) {
				throw new Error(describeMissingAsymmetricMaterial(algorithm, "publicKey", hasSecret));
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

		throw new Error(
			`Unsupported algorithm for local provider: ${algorithm}. ` +
				`Supported values: ${SUPPORTED_ALGORITHMS.join(", ")}.`,
		);
	});
}
