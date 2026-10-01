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

import { createSecretKey } from "node:crypto";
import {
	createSymmetricKeyStore,
	type GrantResult,
	type KeyStore,
	type RefreshTokenFamilyRevocation,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";
import { expect } from "vitest";

export const SECRET = "test-secret-at-least-32-chars!!";
export const keyStore: KeyStore = createSymmetricKeyStore(SECRET);
export const secretKey = createSecretKey(Buffer.from(SECRET));

export const ISSUER = "https://auth.example";

export async function signSelfIssuedAccessToken(
	claims: Record<string, unknown>,
	options: { expiresIn?: string; typ?: string } = {},
): Promise<string> {
	const { expiresIn = "1h", typ = "at+jwt" } = options;
	return new SignJWT({
		sub: "user-1",
		scope: "read",
		iss: ISSUER,
		aud: "client-a",
		...claims,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ })
		.setIssuedAt()
		.setExpirationTime(expiresIn)
		.sign(secretKey);
}

export function makeFamilyRevocation(
	overrides: Partial<RefreshTokenFamilyRevocation> = {},
): RefreshTokenFamilyRevocation {
	return {
		async isFamilyRevoked() {
			return false;
		},
		async revokeFamily() {},
		...overrides,
	};
}

/** The tokens a grant issued; a result that issued none fails the test, naming it. */
export const tokensOf = (result: GrantResult) =>
	"tokens" in result
		? result.tokens
		: expect.fail(`expected tokens, got ${JSON.stringify(result)}`);
