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
 * #542 — the id_token's signature is verified against Google's JWKS.
 *
 * openid-client 6 treats an id_token returned by the token endpoint as
 * delivered over TLS and does not verify its signature on the code flow
 * unless `enableNonRepudiationChecks` is on; a `jwks_uri` in the metadata
 * fetches nothing by itself. The provider's comments said otherwise, and
 * nothing exercised the claim. These cases run the real library against a
 * fake Google that records every request and signs real RS256 tokens, so what
 * is asserted is what the code does.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createGoogleProvider, type GoogleProvider } from "../google.mjs";
import { createFakeIdp } from "./fake-idp.mjs";

const GOOGLE = {
	issuer: "https://accounts.google.com",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
};
const CALLBACK = "https://app.example.com/session/oauth/federation/google/callback";
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";

const build = async () => {
	const idp = await createFakeIdp({ ...GOOGLE, clientId: "client-id" });
	idp.nonce = "nonce-1";
	const provider = createGoogleProvider({
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: CALLBACK,
		fetch: idp.fetch,
	});
	return { idp, provider };
};

const exchange = (provider: GoogleProvider) =>
	provider.exchangeCode({
		code: "code-1",
		codeVerifier: VERIFIER,
		redirectUri: CALLBACK,
		nonce: "nonce-1",
	});

describe("Google id_token signature verification (#542)", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("fetches Google's JWKS on exchange and accepts an id_token signed by a published key", async () => {
		const { idp, provider } = await build();
		const profile = await exchange(provider);
		expect(profile.sub).toBe(idp.sub);
		// Before #542 this was zero: the token was accepted without a key.
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(1);
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(1);
		expect(idp.requestsTo(GOOGLE.userinfoEndpoint)).toHaveLength(1);
	});

	it("refuses an id_token signed by a key Google never published, even under the published kid", async () => {
		// A well-formed RS256 signature by the wrong key — what a party inside
		// the token endpoint's TLS session, or holding a stolen kid, would
		// present. Only checking the bytes against the JWKS catches it.
		const { idp, provider } = await build();
		idp.signWithUnpublishedKey = true;
		await expect(exchange(provider)).rejects.toThrow();
		expect(idp.requestsTo(GOOGLE.userinfoEndpoint)).toHaveLength(0);
	});

	it("refuses a kid no published key matches, even after refetching the JWKS", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-09-12T00:00:00Z"));
		const { idp, provider } = await build();
		await exchange(provider);

		idp.signingKid = "kid-ghost";
		vi.setSystemTime(new Date("2026-09-12T00:01:01Z"));
		await expect(exchange(provider)).rejects.toThrow();
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(2);
		expect(idp.requestsTo(GOOGLE.userinfoEndpoint)).toHaveLength(1);
	});

	it("picks up a rotated signing key once the cached JWKS is a minute old", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-09-12T00:00:00Z"));
		const { idp, provider } = await build();
		await exchange(provider);
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(1);

		expect(await idp.rotateKey()).toBe("kid-2");
		// The library refuses to refetch a JWKS it fetched under a minute ago,
		// so a token under a brand-new kid is refused until the cache ages —
		// which is why an IdP publishes a key before signing with it.
		await expect(exchange(provider)).rejects.toThrow();
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(1);

		vi.setSystemTime(new Date("2026-09-12T00:01:01Z"));
		const profile = await exchange(provider);
		expect(profile.sub).toBe(idp.sub);
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(2);
	});

	it("still refuses a nonce that is not the transaction's, before any userinfo call", async () => {
		const { idp, provider } = await build();
		idp.nonce = "nonce-from-another-transaction";
		await expect(exchange(provider)).rejects.toThrow();
		expect(idp.requestsTo(GOOGLE.userinfoEndpoint)).toHaveLength(0);
	});

	it("accepts a refresh whose id_token is signed by a published key", async () => {
		const { idp, provider } = await build();
		await exchange(provider);
		const refreshed = await provider.refreshToken("rt-1");
		expect(refreshed.accessToken).toBe("at-refreshed");
		expect(refreshed.idToken).toBeDefined();
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(2);
	});

	it("refuses a refresh whose id_token is signed by a key Google never published", async () => {
		const { idp, provider } = await build();
		await exchange(provider);
		idp.signWithUnpublishedKey = true;
		await expect(provider.refreshToken("rt-1")).rejects.toThrow();
	});
});
