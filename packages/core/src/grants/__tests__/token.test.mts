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
import { describe, expect, it } from "vitest";
import { decodeProtectedHeader } from "jose";
import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { generateToken, generateTokenResponse } from "../token.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

describe("generateToken", () => {
	it("returns a Token with a valid JWT string", async () => {
		const token = await generateToken({ user: "alice" }, {
			keyStore,
			expiresIn: 3600,
			type: "access",
		});

		expect(token.token).toBeDefined();
		expect(typeof token.token).toBe("string");
		expect(token.token.split(".")).toHaveLength(3);
	});

	it("sets kid in JWT protected header", async () => {
		const token = await generateToken({ user: "alice" }, {
			keyStore,
			type: "access",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.alg).toBe("HS256");
		expect(header.kid).toBe("v0");
	});

	it("sets custom kid from keyStore", async () => {
		const ks = createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v2");
		const token = await generateToken({ user: "alice" }, {
			keyStore: ks,
			type: "access",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.kid).toBe("v2");
	});

	it("includes expiresIn, audience, issuer, scopes, type in result", async () => {
		const token = await generateToken({ user: "alice" }, {
			keyStore,
			expiresIn: 3600,
			issuer: "auth.provider",
			audience: "client1",
			scopes: ["read", "write"],
			type: "access",
		});

		expect(token.expiresIn).toBe(3600);
		expect(token.issuer).toBe("auth.provider");
		expect(token.audience).toBe("client1");
		expect(token.scopes).toEqual(["read", "write"]);
		expect(token.type).toBe("access");
	});

	it("omits optional fields when not provided", async () => {
		const token = await generateToken({ user: "alice" }, { keyStore });

		expect(token.expiresIn).toBeUndefined();
		expect(token.issuer).toBeUndefined();
		expect(token.audience).toBeUndefined();
		expect(token.scopes).toBeUndefined();
		expect(token.type).toBeUndefined();
	});
});

describe("generateTokenResponse", () => {
	it("formats access token response", async () => {
		const accessToken = await generateToken({ user: "alice" }, {
			keyStore,
			expiresIn: 3600,
			scopes: ["read"],
			type: "access",
		});

		const response = generateTokenResponse({ accessToken });

		expect(response.access_token).toBe(accessToken.token);
		expect(response.token_type).toBe("Bearer");
		expect(response.expires_in).toBe(3600);
		expect(response.scope).toBe("read");
		expect(response.refresh_token).toBeUndefined();
	});

	it("includes refresh token when provided", async () => {
		const accessToken = await generateToken({}, { keyStore, type: "access" });
		const refreshToken = await generateToken({}, { keyStore, type: "refresh" });

		const response = generateTokenResponse({ accessToken, refreshToken });

		expect(response.refresh_token).toBe(refreshToken.token);
	});
});
