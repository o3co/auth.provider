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
 * A token response's `expires_in` is the time the access token has left when
 * the response is built (RFC 6749 §5.1), never more than its lifetime and
 * never below zero.
 */

import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateToken, generateTokenResponse } from "#/grants/token.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
const T0 = 1_790_000_000;
const LIFETIME = 300;

const at = (seconds: number) => vi.spyOn(Date, "now").mockReturnValue(seconds * 1000);

afterEach(() => {
	vi.restoreAllMocks();
});

const mint = () => generateToken({}, { keyStore, expiresIn: LIFETIME, issuedAt: T0 });

describe("generateToken reports the expiry it signed", () => {
	it("as expiresAt, the token's exp in whole seconds", async () => {
		const token = await mint();
		expect(token.expiresAt).toBe(T0 + LIFETIME);
		expect(decodeJwt(token.token).exp).toBe(token.expiresAt);
	});

	it("not at all for a token with no exp", async () => {
		const token = await generateToken({}, { keyStore, issuedAt: T0 });
		expect(token).not.toHaveProperty("expiresAt");
	});
});

describe("generateTokenResponse answers expires_in as the time left", () => {
	it("is the lifetime less the seconds since iat: a grant whose signing took 30 s reports lifetime − 30", async () => {
		const token = await mint();
		at(T0 + 30);
		expect(generateTokenResponse({ accessToken: token }).expires_in).toBe(LIFETIME - 30);
	});

	it("counts whole seconds elapsed, not a partial one", async () => {
		const token = await mint();
		at(T0 + 30.9);
		expect(generateTokenResponse({ accessToken: token }).expires_in).toBe(LIFETIME - 30);
	});

	it("is never above the lifetime, even when the clock stepped back", async () => {
		const token = await mint();
		at(T0 - 120);
		expect(generateTokenResponse({ accessToken: token }).expires_in).toBe(LIFETIME);
	});

	it("is 0 once the lifetime has elapsed", async () => {
		const token = await mint();
		for (const later of [LIFETIME, LIFETIME + 1, LIFETIME + 3600]) {
			at(T0 + later);
			expect(generateTokenResponse({ accessToken: token }).expires_in, String(later)).toBe(0);
		}
	});

	it("is the lifetime as given for a token without expiresAt, as before", () => {
		at(T0 + 30);
		expect(
			generateTokenResponse({ accessToken: { token: "t", expiresIn: LIFETIME } }).expires_in,
		).toBe(LIFETIME);
		expect(generateTokenResponse({ accessToken: { token: "t" } })).not.toHaveProperty("expires_in");
	});
});
