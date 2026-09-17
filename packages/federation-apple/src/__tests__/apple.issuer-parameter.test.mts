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
 * #597 — an RFC 9207 `iss` in Apple's posted callback reaches the library's
 * issuer check.
 *
 * Apple's discovery document does not advertise
 * `authorization_response_iss_parameter_supported`, so the parameter is not
 * required here. One that is sent is compared with Apple's issuer. These cases
 * run the real library against a fake Apple, as the #542 cases do.
 */

import { describe, expect, it } from "vitest";
import { type AppleProvider, createAppleProvider } from "../apple.mjs";
import { createFakeIdp } from "./fake-idp.mjs";

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

const exchangeWith = (provider: AppleProvider, callbackParams: Readonly<Record<string, string>>) =>
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

describe("Apple authorization response issuer (RFC 9207, #597)", () => {
	it("refuses another issuer's iss before any token request", async () => {
		const { idp, provider } = await build();
		await expect(exchangeWith(provider, { iss: "https://impostor.test" })).rejects.toMatchObject(
			refusedBecause(/unexpected "iss"/),
		);
		expect(idp.requestsTo(APPLE.tokenEndpoint)).toHaveLength(0);
	});

	it("accepts Apple's own iss", async () => {
		const { idp, provider } = await build();
		const profile = await exchangeWith(provider, { iss: APPLE.issuer });
		expect(profile.sub).toBe(idp.sub);
	});

	it("does not require one: Apple does not advertise the parameter", async () => {
		const { idp, provider } = await build();
		const profile = await exchangeWith(provider, {});
		expect(profile.sub).toBe(idp.sub);
	});

	it("forwards iss and nothing else: the first-authorization `user` body stays out of the URL", async () => {
		const { idp, provider } = await build();
		const profile = await exchangeWith(provider, {
			iss: APPLE.issuer,
			user: '{"name":{"firstName":"Alice","lastName":"Example"}}',
			error: "access_denied",
			id_token: "hybrid.id.token",
		});
		expect(profile.sub).toBe(idp.sub);
		expect(profile.name).toBe("Alice Example");
	});
});
