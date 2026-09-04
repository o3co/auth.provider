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

import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";

export type TestIdTokenClaims = {
	iss?: string;
	aud?: string | readonly string[];
	sub?: string;
	nonce?: string;
	iat?: number;
	exp?: number;
	[key: string]: unknown;
};

export type TestIdTokenResult = {
	readonly jwt: string;
	readonly jwks: { readonly keys: readonly object[] };
	readonly sub: string;
	readonly claims: Record<string, unknown>;
};

const DEFAULT_ISSUER = "https://appleid.apple.com";
const DEFAULT_AUD = "com.example.app.service";
/** Apple's `sub` is a stable opaque team-scoped identifier, not a number. */
const DEFAULT_SUB = "000123.7f4c1b9e0a2d4f8b93c1a6d5e0f27b41.0456";

/**
 * Mint a realistic RS256-signed Apple id_token. Apple signs with RS256 and
 * publishes the keys at `https://appleid.apple.com/auth/keys`; the provider
 * verifies through openid-client, which the unit tests mock, so this exists to
 * give those mocks realistic inputs rather than opaque placeholders.
 *
 * Note the claims it defaults to: `email_verified` and `is_private_email` are
 * the **strings** `"true"`, which is one of the shapes Apple actually sends.
 */
export async function makeTestAppleIdToken(
	overrides: TestIdTokenClaims = {},
): Promise<TestIdTokenResult> {
	const { publicKey, privateKey } = await generateKeyPair("RS256");
	const now = Math.floor(Date.now() / 1000);
	const sub = typeof overrides.sub === "string" ? overrides.sub : DEFAULT_SUB;

	const claims: Record<string, unknown> = {
		iss: DEFAULT_ISSUER,
		aud: DEFAULT_AUD,
		sub,
		nonce: "test-nonce-from-session",
		email: "sxyz1a2b3c@privaterelay.appleid.com",
		email_verified: "true",
		is_private_email: "true",
		iat: now,
		exp: now + 3600,
		...overrides,
	};

	const jwt = await new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256", kid: "test-apple-kid" })
		.sign(privateKey);

	const jwk = await exportJWK(publicKey);
	const jwks = { keys: [{ ...jwk, kid: "test-apple-kid", use: "sig", alg: "RS256" }] };

	return { jwt, jwks, sub, claims };
}

export type TestSigningKey = {
	/** PKCS#8 PEM — the shape of the `.p8` file downloaded from the Apple Developer portal. */
	readonly privateKeyPem: string;
	/** JWK of the matching public key, for verifying a generated client secret. */
	readonly publicJwk: Record<string, unknown>;
	readonly publicKey: CryptoKey;
};

/**
 * Generate an EC P-256 key pair and export the private half as PKCS#8 PEM —
 * byte-shape-identical to the `AuthKey_XXXXXXXXXX.p8` Apple hands out.
 */
export async function makeTestSigningKey(): Promise<TestSigningKey> {
	const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
	return {
		privateKeyPem: await exportPKCS8(privateKey),
		publicJwk: (await exportJWK(publicKey)) as Record<string, unknown>,
		publicKey: publicKey as CryptoKey,
	};
}
