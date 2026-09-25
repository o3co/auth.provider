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

/**
 * The refresh-token family the authorization-code grant opens is registered
 * under the identity of the refresh token it serves: the family record's
 * active `jti` is the token's `jti`, and its expiry is the token's `exp`.
 *
 * The grant used to learn that identity by decoding the token it had just
 * signed, and to skip the registration — and serve the token anyway — when
 * the decode did not yield a string `jti` and a numeric `exp`. A token served
 * with no family record has no rotation record either, so every replay of it
 * reads as a first use (RFC 6819 §5.2.2.3). Before the refresh lifetime was
 * read when the grant is built, a configuration without one reached that
 * skip; since then, a `KeyStore` whose `sign` returns anything other than a
 * compact JWS over the claims it was handed does. Here that is a signer that
 * nests the signed token in an encrypted JWT (RFC 7519 §5.2), which is still
 * the token this grant minted, but not one it can read back unverified.
 *
 * Driven through the real grant and core's real family store and rotation;
 * only `register` is spied, and it calls the real one.
 */

import crypto from "node:crypto";
import {
	type CodeRepository,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantDependencies,
	type KeyStore,
	type RefreshTokenFamilyStore,
} from "@o3co/auth-provider-core";
import { CompactEncrypt, compactDecrypt, decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";

const RP_URI = "https://rp.example/cb";
const CLIENT_ID = "client1";
const REFRESH_TOKEN_TTL = 86_400;
const CODE_VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(CODE_VERIFIER).digest("base64url");

const config = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: REFRESH_TOKEN_TTL },
		grants: { authorization_code: { enabled: true } },
	},
} as unknown as GrantDependencies["config"];

const signing = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

/**
 * A signer that encrypts what it signs: the JWS a symmetric keystore makes,
 * nested in a `dir` / `A256GCM` JWE. Everything but `sign` is the symmetric
 * keystore's.
 */
function nestingKeyStore(encryptionKey: Uint8Array): KeyStore {
	return {
		algorithm: signing.algorithm,
		async sign(options) {
			const jws = await signing.sign(options);
			return new CompactEncrypt(new TextEncoder().encode(jws))
				.setProtectedHeader({ alg: "dir", enc: "A256GCM", cty: "JWT" })
				.encrypt(encryptionKey);
		},
		getSigningKidFallback: () => signing.getSigningKidFallback(),
		getVerificationKeys: () => signing.getVerificationKeys(),
		getVerificationKey: (kid) => signing.getVerificationKey(kid),
	};
}

async function exchangeCode(keyStore: KeyStore) {
	const refreshTokenFamilyStore: RefreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore,
		accessTokenHorizonMs: 3_600_000,
	});
	const register = vi.fn(rotation.register);
	const handler = createAuthorizationGrant({
		config,
		keyStore,
		clientRepository: { findById: async () => null, authenticate: async () => null },
		codeRepository: {
			consumeByCode: async () =>
				codeRecord({
					code: "the-code",
					client_id: CLIENT_ID,
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
					grantedScope: ["read"],
				}),
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		refreshTokenFamilyRotation: { ...rotation, register },
	});
	const { result } = await handler.handle({
		body: {
			code: "the-code",
			client_id: CLIENT_ID,
			redirect_uri: RP_URI,
			code_verifier: CODE_VERIFIER,
		},
		session: { user: { id: "u1" } },
		issuer: "https://auth.example",
		metadata: { ip: "127.0.0.1" },
		authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
	});
	return { result, register, refreshTokenFamilyStore };
}

describe("authorization_code — the refresh-token family it registers", () => {
	it("is registered under the served refresh token's own jti and exp", async () => {
		const { result, register, refreshTokenFamilyStore } = await exchangeCode(signing);

		if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
		const refreshToken = decodeJwt(result.tokens.refresh_token as string);
		expect((refreshToken.exp as number) - (refreshToken.iat as number)).toBe(REFRESH_TOKEN_TTL);
		expect(register).toHaveBeenCalledTimes(1);
		expect(register).toHaveBeenCalledWith(
			refreshToken.jti,
			refreshToken.family_id,
			(refreshToken.exp as number) * 1000,
		);
		const family = await refreshTokenFamilyStore.findFamily(refreshToken.family_id as string);
		expect(family).toMatchObject({
			activeJti: refreshToken.jti,
			expiresAtMs: (refreshToken.exp as number) * 1000,
			revoked: false,
		});
	});

	it("is registered whatever form the signer returns the token in, never skipped", async () => {
		const encryptionKey = crypto.randomBytes(32);
		const { result, register, refreshTokenFamilyStore } = await exchangeCode(
			nestingKeyStore(encryptionKey),
		);

		if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
		// The token served is the one registered: open the nesting and compare.
		const { plaintext } = await compactDecrypt(
			result.tokens.refresh_token as string,
			encryptionKey,
		);
		const refreshToken = decodeJwt(new TextDecoder().decode(plaintext));
		expect(register).toHaveBeenCalledTimes(1);
		expect(register).toHaveBeenCalledWith(
			refreshToken.jti,
			refreshToken.family_id,
			(refreshToken.exp as number) * 1000,
		);
		const family = await refreshTokenFamilyStore.findFamily(refreshToken.family_id as string);
		expect(family).toMatchObject({
			activeJti: refreshToken.jti,
			expiresAtMs: (refreshToken.exp as number) * 1000,
		});
	});
});
