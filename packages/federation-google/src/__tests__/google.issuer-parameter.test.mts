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
 * #597 — the RFC 9207 `iss` authorization-response parameter reaches the
 * library's issuer check.
 *
 * Google's discovery document advertises
 * `authorization_response_iss_parameter_supported`, and its OpenID Connect
 * reference says of the authorization response's `iss`: "Per RFC 9207, this
 * parameter is always returned and set to https://accounts.google.com". The
 * provider used to rebuild the callback URL from the code alone, so the
 * comparison never ran, and its hand-built metadata never asked for the
 * parameter. These cases run the real library against a fake Google, as the
 * #542 cases do.
 */

import { describe, expect, it } from "vitest";
import {
	createGoogleProvider,
	type GoogleProvider,
	type GoogleProviderConfig,
} from "../google.mjs";
import { createFakeIdp } from "./fake-idp.mjs";

const GOOGLE = {
	issuer: "https://accounts.google.com",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
};
const CALLBACK = "https://app.example.com/session/oauth/federation/google/callback";
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";

const build = async (overrides: Partial<GoogleProviderConfig> = {}) => {
	const idp = await createFakeIdp({ ...GOOGLE, clientId: "client-id" });
	idp.nonce = "nonce-1";
	const provider = createGoogleProvider({
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: CALLBACK,
		fetch: idp.fetch,
		...overrides,
	});
	return { idp, provider };
};

const exchangeWith = (provider: GoogleProvider, callbackParams: Readonly<Record<string, string>>) =>
	provider.exchangeCode({
		code: "code-1",
		codeVerifier: VERIFIER,
		redirectUri: CALLBACK,
		nonce: "nonce-1",
		callbackParams,
	});

// openid-client reports every response failure as "invalid response
// encountered" and carries the reason on `cause`.
const refusedBecause = (reason: RegExp) => ({
	code: "OAUTH_INVALID_RESPONSE",
	cause: { message: expect.stringMatching(reason) },
});

describe("Google authorization response issuer (RFC 9207, #597)", () => {
	it("accepts Google's own iss", async () => {
		const { idp, provider } = await build();
		const profile = await exchangeWith(provider, { iss: GOOGLE.issuer });
		expect(profile.sub).toBe(idp.sub);
	});

	it("refuses another issuer's iss before any token request", async () => {
		const { idp, provider } = await build();
		await expect(exchangeWith(provider, { iss: "https://impostor.test" })).rejects.toMatchObject(
			refusedBecause(/unexpected "iss"/),
		);
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(0);
	});

	it("refuses a callback with no iss: Google always sends one, so its absence is the anomaly", async () => {
		const { idp, provider } = await build();
		await expect(exchangeWith(provider, {})).rejects.toMatchObject(
			refusedBecause(/"iss" \(issuer\) missing/),
		);
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(0);
	});

	it("compares iss as an exact string: a trailing slash is another issuer", async () => {
		const { idp, provider } = await build();
		await expect(
			exchangeWith(provider, { iss: "https://accounts.google.com/" }),
		).rejects.toMatchObject(refusedBecause(/unexpected "iss"/));
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(0);
	});

	it("treats an empty iss as absent", async () => {
		const { idp, provider } = await build();
		await expect(exchangeWith(provider, { iss: "" })).rejects.toMatchObject(
			refusedBecause(/"iss" \(issuer\) missing/),
		);
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(0);
	});

	describe("requireAuthorizationResponseIss = false, the operator's escape hatch", () => {
		it("accepts a callback with no iss", async () => {
			const { idp, provider } = await build({ requireAuthorizationResponseIss: false });
			const profile = await exchangeWith(provider, {});
			expect(profile.sub).toBe(idp.sub);
		});

		it("refuses a value that is not a boolean, at construction", () => {
			// An environment override arrives as the STRING "false", which is
			// truthy: a hand-written bridge that forwards it uncoerced would leave
			// the requirement on, during the very incident the switch is for.
			for (const bad of ["false", "true", 0, null]) {
				expect(() =>
					createGoogleProvider({
						clientId: "client-id",
						clientSecret: "client-secret",
						callbackURL: CALLBACK,
						requireAuthorizationResponseIss: bad as unknown as boolean,
					}),
				).toThrow(/requireAuthorizationResponseIss must be a boolean/);
			}
		});

		it("still refuses another issuer's iss", async () => {
			const { idp, provider } = await build({ requireAuthorizationResponseIss: false });
			await expect(exchangeWith(provider, { iss: "https://impostor.test" })).rejects.toMatchObject(
				refusedBecause(/unexpected "iss"/),
			);
			expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(0);
		});
	});

	it("forwards iss and nothing else from the callback bag", async () => {
		const { idp, provider } = await build();
		const profile = await exchangeWith(provider, {
			iss: GOOGLE.issuer,
			error: "access_denied",
			response: "jarm.response.jwt",
			id_token: "hybrid.id.token",
			token: "implicit-access-token",
		});
		expect(profile.sub).toBe(idp.sub);
	});
});
