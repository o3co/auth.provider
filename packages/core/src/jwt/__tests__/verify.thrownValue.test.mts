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
 * The key a keystore answers is an adapter's, and verifying with it may throw
 * anything. Whatever is thrown, the verifier refuses the token with its own
 * `JwtVerificationError` and never rethrows what it could not inspect.
 */

import { createSecretKey } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { type JwtVerifyOptions, verifyJwt } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore, type KeyStore } from "#/keys/KeyStore.mjs";

const SECRET = "test-secret-32-bytes-long-string12";
const ISSUER = "https://example.com";

const options: JwtVerifyOptions = {
	type: "access_token",
	expectedIssuer: ISSUER,
	revocation: "none",
};

const mint = (): Promise<string> =>
	new SignJWT({ sub: "user-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(createSecretKey(Buffer.from(SECRET)));

/** The real keystore, answering a key that throws `thrown` from whatever reads it. */
const keyStoreWhoseKeyThrows = (thrown: unknown): KeyStore => {
	const real = createSymmetricKeyStore(SECRET, "v0");
	const trap = (): never => {
		throw thrown;
	};
	const key = new Proxy(
		{},
		{
			// Not a thenable, so the keystore's promise resolves to it.
			get: (_target, property) => (property === "then" ? undefined : trap()),
			has: trap,
			getPrototypeOf: trap,
			ownKeys: trap,
		},
	);
	return {
		algorithm: real.algorithm,
		sign: (o) => real.sign(o),
		getSigningKidFallback: () => real.getSigningKidFallback(),
		getVerificationKeys: () => real.getVerificationKeys(),
		getVerificationKey: async () => key as Awaited<ReturnType<KeyStore["getVerificationKey"]>>,
	};
};

describe("verifyJwt — a thrown value it cannot inspect", () => {
	it("refuses the token when what is thrown is a Proxy whose getPrototypeOf trap throws", async () => {
		const thrown = new Proxy(
			{},
			{
				getPrototypeOf() {
					throw new Error("trap");
				},
			},
		);
		await expect(
			verifyJwt(await mint(), keyStoreWhoseKeyThrows(thrown), options),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "signature",
		});
	});

	it("refuses the token when what is thrown is an Error whose message getter throws", async () => {
		const thrown = Object.defineProperty(new Error("x"), "message", {
			get() {
				throw new Error("unreadable");
			},
		});
		await expect(
			verifyJwt(await mint(), keyStoreWhoseKeyThrows(thrown), options),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "signature",
		});
	});

	it("refuses the token when what is thrown is an Error whose prototype chain holds such a Proxy", async () => {
		const trap = new Proxy(
			{},
			{
				getPrototypeOf() {
					throw new Error("trap");
				},
			},
		);
		const thrown = Object.setPrototypeOf(new Error("x"), trap);
		await expect(
			verifyJwt(await mint(), keyStoreWhoseKeyThrows(thrown), options),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "signature",
		});
	});
});
