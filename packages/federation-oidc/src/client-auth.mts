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

import { createPrivateKey, type KeyObject } from "node:crypto";
import { type FederationClientSecret, resolveClientSecret } from "@o3co/auth-provider-session";
import { importPKCS8 } from "jose";
import * as oidc from "openid-client";

/**
 * Client authentication at the upstream token endpoint (#524).
 *
 * Two methods, chosen by which credential the config carries:
 *
 * - `clientSecret` → `client_secret_basic` (RFC 6749 §2.3.1). The secret may
 *   be a resolver, consulted on every token request, so a deployment that
 *   rotates secrets never has to restart.
 * - `privateKey` → `private_key_jwt` (RFC 7523 §2.2 / OIDC Core §9). A
 *   PEM-encoded PKCS#8 key; the JWS algorithm is inferred from the key type
 *   unless `alg` says otherwise, and `kid` is put in the assertion header so
 *   the IdP can pick the key from the client's registered JWKS.
 *
 * Exactly one of the two: a config with both is ambiguous, one with neither
 * cannot authenticate, and each is refused at construction rather than at the
 * first login.
 */
export interface OidcPrivateKey {
	/** PEM-encoded PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`). */
	readonly pem: string;
	/** `kid` for the assertion header, matching the key's entry in the client's JWKS. */
	readonly kid?: string;
	/** JWS algorithm; inferred from the key type when absent (RS256, ES256/384/512, EdDSA). */
	readonly alg?: string;
}

export interface OidcClientCredentials {
	readonly clientSecret?: FederationClientSecret;
	readonly privateKey?: string | OidcPrivateKey;
}

/** `application/x-www-form-urlencoded`, as RFC 6749 §2.3.1 requires before base64. */
const formUrlEncode = (value: string): string =>
	new URLSearchParams([["v", value]]).toString().slice(2);

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** `client_secret_basic` with a secret that may be resolved per request. */
export function clientSecretBasic(clientSecret: FederationClientSecret): oidc.ClientAuth {
	// oauth4webapi awaits the callback, so the resolver can be asynchronous;
	// openid-client's declared type is the synchronous narrowing, hence the cast.
	const auth = async (
		_as: oidc.ServerMetadata,
		client: oidc.ClientMetadata,
		_body: URLSearchParams,
		headers: Headers,
	): Promise<void> => {
		const secret = await resolveClientSecret(clientSecret);
		const credentials = Buffer.from(
			`${formUrlEncode(client.client_id)}:${formUrlEncode(secret)}`,
		).toString("base64");
		headers.set("authorization", `Basic ${credentials}`);
	};
	return auth as unknown as oidc.ClientAuth;
}

function inferAlg(label: string, key: KeyObject): string {
	switch (key.asymmetricKeyType) {
		case "rsa":
			return "RS256";
		case "rsa-pss":
			return "PS256";
		case "ec": {
			const curve = key.asymmetricKeyDetails?.namedCurve;
			if (curve === "prime256v1") return "ES256";
			if (curve === "secp384r1") return "ES384";
			if (curve === "secp521r1") return "ES512";
			if (curve === "secp256k1") return "ES256K";
			throw new Error(
				`${label}: privateKey uses EC curve ${String(curve)}, which has no JWS algorithm; set privateKey.alg`,
			);
		}
		case "ed25519":
			return "EdDSA";
		default:
			throw new Error(
				`${label}: privateKey of type ${String(key.asymmetricKeyType)} is not usable for private_key_jwt; set privateKey.alg`,
			);
	}
}

/** `private_key_jwt` from a PEM key, importing it once at construction. */
export async function privateKeyJwt(
	label: string,
	privateKey: string | OidcPrivateKey,
): Promise<oidc.ClientAuth> {
	const spec = typeof privateKey === "string" ? { pem: privateKey } : privateKey;
	if (typeof spec.pem !== "string" || !spec.pem.includes("-----BEGIN")) {
		throw new Error(`${label}: privateKey must be a PEM-encoded PKCS#8 private key`);
	}
	let keyObject: KeyObject;
	try {
		keyObject = createPrivateKey(spec.pem);
	} catch (err) {
		throw new Error(`${label}: privateKey could not be parsed: ${message(err)}`, { cause: err });
	}
	const alg = spec.alg ?? inferAlg(label, keyObject);
	let key: Awaited<ReturnType<typeof importPKCS8>>;
	try {
		key = await importPKCS8(spec.pem, alg, { extractable: false });
	} catch (err) {
		throw new Error(`${label}: privateKey cannot sign ${alg}: ${message(err)}`, { cause: err });
	}
	return oidc.PrivateKeyJwt(spec.kid === undefined ? key : { key, kid: spec.kid });
}

/** The one client authentication method the credentials describe. */
export async function clientAuthFor(
	label: string,
	credentials: OidcClientCredentials,
): Promise<oidc.ClientAuth> {
	const hasSecret = credentials.clientSecret !== undefined;
	const hasKey = credentials.privateKey !== undefined;
	if (hasSecret === hasKey) {
		throw new Error(
			`${label}: set exactly one of clientSecret (client_secret_basic) or privateKey (private_key_jwt)`,
		);
	}
	return hasSecret
		? clientSecretBasic(credentials.clientSecret as FederationClientSecret)
		: privateKeyJwt(label, credentials.privateKey as string | OidcPrivateKey);
}
