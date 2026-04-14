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
import { decodeJwt, decodeProtectedHeader } from "jose";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { generateToken, generateTokenResponse } from "#/grants/token.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

describe("generateToken", () => {
	it("returns a Token with a valid JWT string", async () => {
		const token = await generateToken({}, {
			keyStore,
			expiresIn: 3600,
			tokenType: "at+jwt",
		});

		expect(token.token).toBeDefined();
		expect(typeof token.token).toBe("string");
		expect(token.token.split(".")).toHaveLength(3);
	});

	it("sets kid in JWT protected header", async () => {
		const token = await generateToken({}, {
			keyStore,
			tokenType: "at+jwt",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.alg).toBe("HS256");
		expect(header.kid).toBe("v0");
	});

	it("sets custom kid from keyStore", async () => {
		const ks = createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v2");
		const token = await generateToken({}, {
			keyStore: ks,
			tokenType: "at+jwt",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.kid).toBe("v2");
	});

	it("sets sub claim via subject option", async () => {
		const token = await generateToken({}, {
			keyStore,
			subject: "user-123",
			tokenType: "at+jwt",
		});

		const payload = decodeJwt(token.token);
		expect(payload.sub).toBe("user-123");
		expect(token.subject).toBe("user-123");
	});

	it("sets azp claim via authorizedParty option", async () => {
		const token = await generateToken({}, {
			keyStore,
			authorizedParty: "client-abc",
			tokenType: "at+jwt",
		});

		const payload = decodeJwt(token.token);
		expect((payload as Record<string, unknown>).azp).toBe("client-abc");
	});

	it("sets scope claim as string in payload", async () => {
		const token = await generateToken({}, {
			keyStore,
			scope: "read write",
			tokenType: "at+jwt",
		});

		const payload = decodeJwt(token.token);
		expect((payload as Record<string, unknown>).scope).toBe("read write");
		expect(token.scope).toBe("read write");
	});

	it("sets typ in protected header via tokenType option", async () => {
		const token = await generateToken({}, {
			keyStore,
			tokenType: "at+jwt",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.typ).toBe("at+jwt");
		expect(token.tokenType).toBe("at+jwt");
	});

	it("sets typ to rt+jwt for refresh tokens", async () => {
		const token = await generateToken({}, {
			keyStore,
			tokenType: "rt+jwt",
		});

		const header = decodeProtectedHeader(token.token);
		expect(header.typ).toBe("rt+jwt");
		expect(token.tokenType).toBe("rt+jwt");
	});

	it("does not include legacy user, client, scopes, type, ip in payload", async () => {
		const token = await generateToken({}, {
			keyStore,
			subject: "user-123",
			authorizedParty: "client-abc",
			scope: "read",
			tokenType: "at+jwt",
		});

		const payload = decodeJwt(token.token) as Record<string, unknown>;
		expect(payload.user).toBeUndefined();
		expect(payload.client).toBeUndefined();
		expect(payload.scopes).toBeUndefined();
		expect(payload.type).toBeUndefined();
		expect(payload.ip).toBeUndefined();
	});

	it("includes expiresIn, audience, issuer, scope, tokenType in result", async () => {
		const token = await generateToken({}, {
			keyStore,
			expiresIn: 3600,
			issuer: "auth.provider",
			audience: "client1",
			scope: "read write",
			tokenType: "at+jwt",
		});

		expect(token.expiresIn).toBe(3600);
		expect(token.issuer).toBe("auth.provider");
		expect(token.audience).toBe("client1");
		expect(token.scope).toBe("read write");
		expect(token.tokenType).toBe("at+jwt");
	});

	it("omits optional fields when not provided", async () => {
		const token = await generateToken({}, { keyStore, tokenType: "at+jwt" });

		expect(token.expiresIn).toBeUndefined();
		expect(token.issuer).toBeUndefined();
		expect(token.audience).toBeUndefined();
		expect(token.scope).toBeUndefined();
		expect(token.subject).toBeUndefined();
	});

	it("sets jti claim in JWT payload", async () => {
		const token = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const payload = decodeJwt(token.token);
		expect(typeof payload.jti).toBe("string");
		expect(payload.jti).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});

	it("generates a unique jti per token", async () => {
		const t1 = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const t2 = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const p1 = decodeJwt(t1.token);
		const p2 = decodeJwt(t2.token);
		expect(p1.jti).not.toBe(p2.jti);
	});
});

describe("generateTokenResponse", () => {
	it("formats access token response", async () => {
		const accessToken = await generateToken({}, {
			keyStore,
			expiresIn: 3600,
			scope: "read",
			tokenType: "at+jwt",
		});

		const response = generateTokenResponse({ accessToken });

		expect(response.access_token).toBe(accessToken.token);
		expect(response.token_type).toBe("Bearer");
		expect(response.expires_in).toBe(3600);
		expect(response.scope).toBe("read");
		expect(response.refresh_token).toBeUndefined();
	});

	it("includes refresh token when provided", async () => {
		const accessToken = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const refreshToken = await generateToken({}, { keyStore, tokenType: "rt+jwt" });

		const response = generateTokenResponse({ accessToken, refreshToken });

		expect(response.refresh_token).toBe(refreshToken.token);
	});
});
