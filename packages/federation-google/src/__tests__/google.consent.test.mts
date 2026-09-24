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
 * Google issues a refresh token only when the user is shown the consent
 * screen: `access_type=offline` "instructs the Google authorization server to
 * return a refresh token and an access token the first time that your
 * application exchanges an authorization code", and without `prompt` "the
 * user will be prompted only the first time your project requests access".
 * The upstream tokens live per session, so a returning user's new session
 * had no refresh token, and oauth's `POST /oauth/federation/google/token`
 * answered `410 refresh_token_absent` once the access token expired.
 *
 * The real library runs against a fake Google that applies that rule
 * (`refreshTokenOnlyOnConsent`) to authorization requests it is handed as a
 * browser would hand them.
 */

import { createFakeIdp } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	createGoogleProvider,
	type GoogleProvider,
	type GoogleProviderConfig,
} from "../google.mjs";

const GOOGLE = {
	issuer: "https://accounts.google.com",
	authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
};
const CALLBACK = "https://app.example.com/session/oauth/federation/google/callback";
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";

const build = async (overrides: Partial<GoogleProviderConfig> = {}) => {
	const idp = await createFakeIdp({ ...GOOGLE, clientId: "client-id" });
	idp.refreshTokenOnlyOnConsent = true;
	const provider = createGoogleProvider({
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: CALLBACK,
		fetch: idp.fetch,
		...overrides,
	});
	return { idp, provider };
};

/** One sign-in, start to profile: the start route's URL, Google's answer, the callback's exchange. */
const signIn = async (idp: Awaited<ReturnType<typeof createFakeIdp>>, provider: GoogleProvider) => {
	const url = provider.buildAuthorizationUrl({
		redirectUri: CALLBACK,
		state: "state-1",
		codeVerifier: VERIFIER,
		nonce: `nonce-${idp.requests.length}`,
	});
	const { code, iss } = idp.authorize(url);
	const profile = await provider.exchangeCode({
		code,
		codeVerifier: VERIFIER,
		redirectUri: CALLBACK,
		nonce: url.searchParams.get("nonce") ?? "",
		callbackParams: { iss },
	});
	return { url, profile };
};

describe("Google refresh tokens for returning users", () => {
	it("asks for offline access and for the consent screen that issues its refresh token", async () => {
		const { provider } = await build();
		const url = provider.buildAuthorizationUrl({
			redirectUri: CALLBACK,
			state: "s",
			codeVerifier: VERIFIER,
			nonce: "n",
		});
		expect(url.searchParams.get("access_type")).toBe("offline");
		expect(url.searchParams.get("prompt")).toBe("consent");
	});

	it("a returning user's sign-in yields a refresh token, as the first one did", async () => {
		const { idp, provider } = await build();
		const first = await signIn(idp, provider);
		expect(first.profile.refreshToken).toBe("rt-1");

		const returning = await signIn(idp, provider);
		expect(returning.profile.refreshToken).toBe("rt-1");
	});

	it("accessType online asks for neither, and no sign-in yields a refresh token", async () => {
		// A deployment that uses Google for sign-in only: no consent screen on
		// every sign-in, and nothing for the federation token route to refresh.
		const { idp, provider } = await build({ accessType: "online" });
		const first = await signIn(idp, provider);
		expect(first.url.searchParams.has("access_type")).toBe(false);
		expect(first.url.searchParams.has("prompt")).toBe(false);
		expect(first.profile.refreshToken).toBeUndefined();

		const returning = await signIn(idp, provider);
		expect(returning.profile.refreshToken).toBeUndefined();
	});

	it("accessType offline is the default, stated explicitly", async () => {
		const { idp, provider } = await build({ accessType: "offline" });
		await signIn(idp, provider);
		expect((await signIn(idp, provider)).profile.refreshToken).toBe("rt-1");
	});

	it.each([
		["a misspelling", "offine"],
		["Google's parameter name", "access_type"],
		["an environment boolean", "true"],
	])("refuses an accessType that is not offline or online at construction: %s", (_l, value) => {
		expect(() =>
			createGoogleProvider({
				clientId: "client-id",
				clientSecret: "client-secret",
				callbackURL: CALLBACK,
				accessType: value as GoogleProviderConfig["accessType"],
			}),
		).toThrow(/accessType must be "offline" or "online"/);
	});
});
