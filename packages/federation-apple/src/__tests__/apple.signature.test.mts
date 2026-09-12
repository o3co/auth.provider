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
 * #542 — the id_token's signature is verified against Apple's JWKS.
 *
 * openid-client 6 treats an id_token returned by the token endpoint as
 * delivered over TLS and does not verify its signature on the code flow
 * unless `enableNonRepudiationChecks` is on; a `jwks_uri` in the metadata
 * fetches nothing by itself. Apple publishes no userinfo endpoint, so the
 * id_token is the only source of identity here — which makes its signature
 * the only thing standing between the token endpoint's TLS and the account.
 * These cases run the real library against a fake Apple that records every
 * request and signs real RS256 tokens.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
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

const exchange = (provider: AppleProvider) =>
	provider.exchangeCode({
		code: "code-1",
		codeVerifier: VERIFIER,
		redirectUri: CALLBACK,
		nonce: "nonce-1",
	});

describe("Apple id_token signature verification (#542)", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("fetches Apple's JWKS on exchange and accepts an id_token signed by a published key", async () => {
		const { idp, provider } = await build();
		const profile = await exchange(provider);
		expect(profile.sub).toBe(idp.sub);
		expect(profile.email).toBe("alice@example.test");
		// Before #542 this was zero: the token was accepted without a key.
		expect(idp.requestsTo(APPLE.jwksUri)).toHaveLength(1);
		const token = idp.requestsTo(APPLE.tokenEndpoint);
		expect(token).toHaveLength(1);
		// Apple requires client_secret_post; the secret travels in the body.
		expect(token[0]?.body?.get("client_secret")).toBe("static-client-secret");
	});

	it("refuses an id_token signed by a key Apple never published, even under the published kid", async () => {
		const { idp, provider } = await build();
		idp.signWithUnpublishedKey = true;
		await expect(exchange(provider)).rejects.toThrow();
	});

	it("refuses a kid no published key matches, even after refetching the JWKS", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-09-12T00:00:00Z"));
		const { idp, provider } = await build();
		await exchange(provider);

		idp.signingKid = "kid-ghost";
		vi.setSystemTime(new Date("2026-09-12T00:01:01Z"));
		await expect(exchange(provider)).rejects.toThrow();
		expect(idp.requestsTo(APPLE.jwksUri)).toHaveLength(2);
	});

	it("sees a rotated signing key at once, because each token call's configuration fetches the JWKS afresh", async () => {
		// Apple's configuration is rebuilt for every token call (the secret
		// rotates), and openid-client caches the JWKS per configuration: one
		// JWKS request per login, and no minute-old cache to wait out after a
		// rotation. The cost is a request Google's single configuration does
		// not make; the benefit is that a rotation can never be missed.
		const { idp, provider } = await build();
		await exchange(provider);
		expect(idp.requestsTo(APPLE.jwksUri)).toHaveLength(1);

		expect(await idp.rotateKey()).toBe("kid-2");
		const profile = await exchange(provider);
		expect(profile.sub).toBe(idp.sub);
		expect(idp.requestsTo(APPLE.jwksUri)).toHaveLength(2);
	});

	it("verifies the id_token a refresh returns as well", async () => {
		const { idp, provider } = await build();
		await exchange(provider);
		const refreshed = await provider.refreshToken("rt-1");
		expect(refreshed.accessToken).toBe("at-refreshed");
		// Through the seam, on a configuration built for that call.
		expect(idp.requestsTo(APPLE.tokenEndpoint)).toHaveLength(2);
	});
});
