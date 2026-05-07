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

import { exportJWK, generateKeyPair, SignJWT } from "jose";

export type TestIdTokenClaims = {
	iss?: string;
	aud?: string | readonly string[];
	sub?: string;
	nonce?: string;
	azp?: string;
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

const DEFAULT_ISSUER = "https://accounts.google.com";
const DEFAULT_AUD = "test-client-id";
const DEFAULT_SUB = "google-user-123";

/**
 * Mints a realistic RS256-signed id_token for federation provider tests. Returns
 * the signed JWT, a matching JWKS (mountable on a mock `jwks_uri` endpoint), the
 * resolved `sub`, and the full claim set so that mocks of `tokens.claims()` can
 * mirror the JWT body verbatim.
 *
 * Production providers verify id_tokens via openid-client. Tests in this package
 * mock `oidc.authorizationCodeGrant` directly, so this helper exists to give the
 * mock realistic-shaped inputs (rather than opaque `"it"` placeholders) and to
 * pre-compute the JWKS for any test that inspects the verification pipeline at a
 * future integration tier (msw + real openid-client).
 */
export async function makeTestGoogleIdToken(
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
		iat: now,
		exp: now + 3600,
		...overrides,
	};

	const jwt = await new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256", kid: "test-kid-1" })
		.sign(privateKey);

	const jwk = await exportJWK(publicKey);
	const jwks = {
		keys: [{ ...jwk, kid: "test-kid-1", use: "sig", alg: "RS256" }],
	};

	return { jwt, jwks, sub, claims };
}
