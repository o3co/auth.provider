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
	type SessionLifecycle,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings } from "@o3co/auth-provider-core/testing";
import { SignJWT } from "jose";
import { expect } from "vitest";

export const SECRET = "test-secret-at-least-32-chars!!";
export const keyStore: KeyStore = createSymmetricKeyStore(SECRET);
export const secretKey = createSecretKey(Buffer.from(SECRET));

export const ISSUER = "https://auth.example";

/** The token settings a hand-built grant mints within: a 300-second access token. */
export const tokenSettings = createTestOAuthTokenSettings({
	issuer: ISSUER,
	accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 },
});

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

/**
 * A session lifecycle whose `liveness` answers from `store`, read at each
 * call, as core's does for an active record: `live` with the user session,
 * `not_live` when there is none. A read that throws rejects with that error,
 * as core's lifecycle does on an outage. Its other members are not expected
 * to be called.
 */
export function livenessOver(store: Pick<UserSessionStore, "get">): SessionLifecycle {
	const unexpected = async (): Promise<never> => {
		throw new Error("this test's session lifecycle only answers liveness");
	};
	return {
		open: unexpected,
		join: unexpected,
		close: unexpected,
		async liveness(sid) {
			const session = await store.get(sid);
			return session ? { outcome: "live", session } : { outcome: "not_live" };
		},
		federations: unexpected,
		resumePending: unexpected,
	};
}
