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
 * The algorithm this library defaults to, and the one `reference.conf` ships
 * (#282). Asymmetric by default so a relying party can verify from the
 * published JWKS without ever holding a key that can also MINT tokens.
 *
 * EdDSA (Ed25519) rather than RS256: it is fully supported by every layer here
 * (`createAsymmetricKeyStore`, the JWKS route's `exportJWK`, and jose's
 * `importPKCS8`/`importSPKI`), its keys and signatures are the smallest of the
 * supported set, and it has no parameter — key size, padding mode — that an
 * operator can get quietly wrong.
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
 * Build the boot failure for an asymmetric algorithm with no key material.
 *
 * This is the message an operator meets on their first deploy after #282, so
 * it names the exact keys and the exact command rather than stating that
 * something is missing. When a `secret` IS present the operator almost
 * certainly carried an HS256 config forward, so the message closes that loop
 * too — the alternative is a correct-but-baffling "privateKey is required"
 * against a config that visibly has a key in it.
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
 * Narrows config.previousSecrets from unknown to a typed array of
 * SymmetricPreviousSecret. Mirrors narrowPreviousKeysArray (asymmetric)
 * but builds Date objects from ISO strings and validates the shared-secret
 * shape (kid + secret + expiresAt). HS256-only — IH-9 rotation support.
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
		// #282: a retired secret is still a live verification key for the whole
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

export function registerBuiltinKeyStores(factory: KeyStoreFactory): void {
	factory.register("local", async (config) => {
		const rawAlgorithm = config.algorithm;
		// #282: NO fallback. The pre-fix code defaulted an absent `algorithm`
		// to HS256, which meant a composition root that configured nothing at
		// all silently got symmetric signing — the exact "quietly weaker than
		// the operator believes" shape this issue is about. `reference.conf`
		// always supplies the value, so reaching this branch means a
		// programmatic caller left it out, and guessing on their behalf is how
		// the original bug shipped.
		if (typeof rawAlgorithm !== "string" || rawAlgorithm.length === 0) {
			throw new Error(
				"oauth.jwt.signingKey.local.algorithm is not configured (env OAUTH_JWT_ALGORITHM). " +
					`Supported values: ${SUPPORTED_ALGORITHMS.join(", ")}. ` +
					`The shipped default is "${DEFAULT_SIGNING_ALGORITHM}"; there is no implicit fallback.`,
			);
		}
		const algorithm = rawAlgorithm;

		if (algorithm === "HS256") {
			// IH-9 defense-in-depth: the Zod schema's strict HS256 branch
			// already rejects asymmetric-shaped `previousKeys`, but
			// `factory.create()` accepts `Record<string, unknown>` and bypasses
			// the schema — programmatic callers (tests, custom composition
			// roots) could otherwise reproduce the original silent-ignore bug.
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
			// #282: the only pre-fix check was `length === 0`, so a
			// one-character secret built a working HS256 keystore. An HS256
			// secret is not merely a decryption key: anyone who guesses it can
			// MINT tokens for any subject.
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
			// #282, mirror of the HS256 `previousKeys` guard above: the
			// asymmetric schema branch is `.passthrough()`, so a
			// `previousSecrets` block left over from an HS256 config survives
			// validation and used to be silently dropped here — the same
			// silent-rotation-loss bug IH-9 closed in the other direction.
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
