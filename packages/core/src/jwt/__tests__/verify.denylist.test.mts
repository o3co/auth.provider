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
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createMemoryAccessTokenDenylist } from "#/access-token-denylist/memory.mjs";
import { verifyJwt } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore, type KeyStore } from "#/keys/KeyStore.mjs";

const TEST_SECRET = "test-secret-32-bytes-long-string12";
const TEST_KID = "v0";
const TEST_ISSUER = "https://test";
const TEST_AUDIENCE = "https://rs";

function testKeyStore(): KeyStore {
	return createSymmetricKeyStore(TEST_SECRET, TEST_KID);
}

async function mintAccessToken(
	overrides: Partial<{
		expSeconds: number;
		sub: string;
		jti: string;
	}> = {},
): Promise<{ token: string; jti: string }> {
	const secretKey = createSecretKey(Buffer.from(TEST_SECRET));
	const jti = overrides.jti ?? `jti-${Math.random().toString(36).slice(2)}`;
	const nowSeconds = Math.floor(Date.now() / 1000);
	const expSeconds = overrides.expSeconds ?? nowSeconds + 300;
	const token = await new SignJWT({
		iss: TEST_ISSUER,
		aud: TEST_AUDIENCE,
		sub: overrides.sub ?? "u-1",
		jti,
	})
		.setProtectedHeader({ alg: "HS256", kid: TEST_KID, typ: "at+jwt" })
		.setIssuedAt(nowSeconds)
		.setExpirationTime(expSeconds)
		.sign(secretKey);
	return { token, jti };
}

describe("verifyJwt with AccessTokenDenylist", () => {
	it("rejects a revoked token with reason 'revoked'", async () => {
		const denylist = createMemoryAccessTokenDenylist();
		const { token, jti } = await mintAccessToken();
		await denylist.add(jti, Date.now() + 10 * 60 * 1000);

		await expect(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				denylist,
			}),
		).rejects.toMatchObject({ reason: "revoked" });
	});

	it("accepts a non-revoked token (denylist returns false)", async () => {
		const denylist = createMemoryAccessTokenDenylist();
		const { token } = await mintAccessToken();
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
			denylist,
		});
		expect(verified.payload.sub).toBe("u-1");
	});

	it("ignoreExpiration accepts already-expired token", async () => {
		// Expire well beyond default clock skew (300 s) so the "without flag" path
		// actually rejects. clockSkewMs: 0 on that call makes the test hermetic
		// regardless of the current default skew.
		const pastExpSec = Math.floor(Date.now() / 1000) - 600;
		const { token } = await mintAccessToken({ expSeconds: pastExpSec });

		// Without flag → fails with reason "expired"
		await expect(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				clockSkewMs: 0,
			}),
		).rejects.toMatchObject({ reason: "expired" });

		// With flag → passes
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
			ignoreExpiration: true,
		});
		expect(verified.payload.sub).toBe("u-1");
	});

	it("does NOT consult denylist when option is undefined (default)", async () => {
		// Confirms backwards-compat: existing callers (no denylist option) see no behavior change.
		const { token } = await mintAccessToken();
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
		});
		expect(verified.payload.sub).toBe("u-1");
	});
});
