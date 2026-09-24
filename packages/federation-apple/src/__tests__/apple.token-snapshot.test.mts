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
 * What an Apple login and an Apple refresh say about the token they got: the
 * lifetime Apple sent (or `null` when it sent none — never an assumed hour),
 * the token type, and the scope as sent. The same reading every bundled
 * adapter gives, through core's `federationTokenSnapshot`. The real library
 * runs against a fake Apple.
 */

import { createFakeIdp } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type AppleProvider, createAppleProvider } from "../apple.mjs";

const APPLE = {
	issuer: "https://appleid.apple.com",
	tokenEndpoint: "https://appleid.apple.com/auth/token",
	jwksUri: "https://appleid.apple.com/auth/keys",
};
const CALLBACK = "https://app.example.com/session/oauth/federation/apple/callback";
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";

const build = async () => {
	const idp = await createFakeIdp({ ...APPLE, clientId: "com.example.service" });
	idp.nonce = "nonce-1";
	const provider = createAppleProvider({
		clientId: "com.example.service",
		clientSecret: "static-client-secret",
		callbackURL: CALLBACK,
		fetch: idp.fetch,
	});
	return { idp, provider };
};

const exchange = (provider: AppleProvider) =>
	provider.exchangeCode({
		code: "code-1",
		codeVerifier: VERIFIER,
		redirectUri: CALLBACK,
		nonce: "nonce-1",
	});

describe("the token an Apple login and refresh report", () => {
	it("a login reports the lifetime Apple sent, dated when the library handed it over, and the token type", async () => {
		const { provider } = await build();
		const before = Date.now();
		const profile = await exchange(provider);
		expect(profile.expiresIn).toBe(3600);
		expect(profile.tokenType).toBe("bearer");
		const at = (profile.expiresAt as Date).getTime();
		expect(at).toBeGreaterThanOrEqual(before + 3600 * 1000);
		expect(at).toBeLessThanOrEqual(Date.now() + 3600 * 1000);
	});

	it("a login whose answer names no lifetime reports none — expiresAt and expiresIn null", async () => {
		const { idp, provider } = await build();
		idp.codeAnswer = { expires_in: undefined };
		const profile = await exchange(provider);
		expect(profile.expiresAt).toBeNull();
		expect(profile.expiresIn).toBeNull();
	});

	it("a refresh reports the lifetime Apple sent and the token type", async () => {
		const { provider } = await build();
		const refreshed = await provider.refreshToken("rt-1");
		expect(refreshed.expiresIn).toBe(1800);
		expect(refreshed.tokenType).toBe("bearer");
		expect(refreshed.expiresAt).toBeInstanceOf(Date);
	});

	it("a refresh whose answer names no lifetime reports none", async () => {
		const { idp, provider } = await build();
		idp.refreshAnswer = { expires_in: undefined };
		const refreshed = await provider.refreshToken("rt-1");
		expect(refreshed.expiresAt).toBeNull();
		expect(refreshed.expiresIn).toBeNull();
	});

	it("a scope that is not a string never reaches the adapter: openid-client refuses the answer", async () => {
		// Why the adapter reads `scope` as a string or nothing: the library
		// refuses any other shape first, at the code exchange and the refresh.
		const { idp, provider } = await build();
		idp.codeAnswer = { scope: 42 };
		await expect(exchange(provider)).rejects.toMatchObject({ code: "OAUTH_INVALID_RESPONSE" });
		idp.refreshAnswer = { scope: ["name", "email"] };
		await expect(provider.refreshToken("rt-1")).rejects.toMatchObject({
			code: "OAUTH_INVALID_RESPONSE",
		});
	});
});
