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

import { generateKeyPairSync } from "node:crypto";
import { codeChallenge, supportsLogout, supportsRefresh } from "@o3co/auth-provider-session";
import { jwtVerify } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOidcProvider, DEFAULT_OIDC_SCOPES, type OidcProviderConfig } from "#/oidc.mjs";
import { createFakeIdp, type FakeIdp } from "./helpers.mjs";

const ISSUER = "https://idp-a.test";
const CALLBACK = "https://auth.test/session/oauth/federation/idp-a/callback";
// A space and a plus, so the Basic header proves the RFC 6749 §2.3.1
// form-url-encoding rather than a bare join.
const SECRET = "s3cret with space+plus";
const VERIFIER = "v".repeat(43);

const baseConfig = (
	idp: FakeIdp,
	overrides: Partial<OidcProviderConfig> = {},
): OidcProviderConfig => ({
	issuer: idp.issuer,
	clientId: idp.clientId,
	clientSecret: SECRET,
	callbackURL: CALLBACK,
	fetch: idp.fetch,
	...overrides,
});

async function build(
	overrides: Partial<OidcProviderConfig> = {},
	idpOptions: Partial<Parameters<typeof createFakeIdp>[0]> = {},
) {
	const idp = await createFakeIdp({ issuer: ISSUER, ...idpOptions });
	const provider = await createOidcProvider("idp-a", baseConfig(idp, overrides));
	return { idp, provider };
}

const exchange = (provider: Awaited<ReturnType<typeof createOidcProvider>>, nonce = "nonce-1") =>
	provider.exchangeCode({ code: "code-1", codeVerifier: VERIFIER, redirectUri: CALLBACK, nonce });

const authorize = (provider: Awaited<ReturnType<typeof createOidcProvider>>, nonce?: string) =>
	provider.buildAuthorizationUrl({
		redirectUri: CALLBACK,
		state: "state-1",
		codeVerifier: VERIFIER,
		nonce,
	});

const basic = (clientId: string, secret: string): string =>
	`Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;

afterEach(() => {
	vi.useRealTimers();
});

describe("createOidcProvider (#524)", () => {
	describe("discovery at construction", () => {
		it("resolves the issuer's metadata once and builds the provider from it", async () => {
			const { idp, provider } = await build();
			expect(idp.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
			expect(provider.name).toBe("idp-a");
			expect(provider.scope).toEqual([...DEFAULT_OIDC_SCOPES]);
			const url = authorize(provider, "n");
			expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/authorize`);
		});

		it("refuses an empty clientSecret at construction, not at the first token request", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			await expect(
				createOidcProvider("idp-a", baseConfig(idp, { clientSecret: "" })),
			).rejects.toThrow(/clientSecret must not be empty/);
		});

		it("is fatal when the document cannot be fetched", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			idp.discoveryStatus = 503;
			await expect(createOidcProvider("idp-a", baseConfig(idp))).rejects.toThrow(
				/OIDC federation "idp-a"[\s\S]*discovery/,
			);
		});

		it("is fatal when the document names a different issuer", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			idp.metadata.issuer = "https://impostor.test";
			await expect(createOidcProvider("idp-a", baseConfig(idp))).rejects.toThrow(
				/OIDC federation "idp-a"[\s\S]*discovery/,
			);
		});

		it("is fatal when the document publishes no jwks_uri", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			delete idp.metadata.jwks_uri;
			await expect(createOidcProvider("idp-a", baseConfig(idp))).rejects.toThrow(/jwks_uri/);
		});

		it("refuses a plain-http issuer unless it is loopback", async () => {
			const remote = await createFakeIdp({ issuer: "http://idp-a.test" });
			await expect(createOidcProvider("idp-a", baseConfig(remote))).rejects.toThrow(/https/);

			const local = await createFakeIdp({ issuer: "http://localhost:8080/realms/dev" });
			const provider = await createOidcProvider("dev", baseConfig(local));
			expect(local.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
			expect(
				authorize(provider, "n").href.startsWith("http://localhost:8080/realms/dev/authorize"),
			).toBe(true);
		});

		it("lets an explicit endpoint override the discovered value", async () => {
			const { idp, provider } = await build({
				endpoints: { authorizationEndpoint: `${ISSUER}/oauth2/v1/authorize` },
			});
			expect(idp.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
			const url = authorize(provider, "n");
			expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/oauth2/v1/authorize`);
		});

		it("discovery = false builds from the hand-typed endpoints and never fetches the document", async () => {
			const { idp, provider } = await build({
				discovery: false,
				endpoints: {
					authorizationEndpoint: `${ISSUER}/authorize`,
					tokenEndpoint: `${ISSUER}/token`,
					jwksUri: `${ISSUER}/jwks`,
					userinfoEndpoint: `${ISSUER}/userinfo`,
				},
			});
			expect(idp.requestsTo("/.well-known/openid-configuration")).toHaveLength(0);
			idp.nonce = "nonce-1";
			const profile = await exchange(provider);
			expect(profile.sub).toBe(idp.sub);
			expect(idp.requestsTo("/jwks")).toHaveLength(1);
		});

		it("discovery = false without every endpoint refuses to build", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			await expect(
				createOidcProvider(
					"idp-a",
					baseConfig(idp, {
						discovery: false,
						endpoints: {
							authorizationEndpoint: `${ISSUER}/authorize`,
							tokenEndpoint: `${ISSUER}/token`,
						},
					}),
				),
			).rejects.toThrow(/jwksUri/);
			expect(idp.requests).toHaveLength(0);
		});
	});

	describe("client authentication", () => {
		it("client_secret_basic by default: the RFC 6749 §2.3.1 header, nothing in the body", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			await exchange(provider);
			const req = idp.lastTokenRequest();
			expect(req?.headers.get("authorization")).toBe(
				basic(idp.clientId, "s3cret+with+space%2Bplus"),
			);
			expect(req?.body?.has("client_secret")).toBe(false);
		});

		it("resolves a rotating secret on every token request", async () => {
			const secrets = ["first-secret", "second-secret"];
			const { idp, provider } = await build({ clientSecret: async () => secrets.shift() ?? "" });
			idp.nonce = "nonce-1";
			await exchange(provider);
			await exchange(provider);
			const [first, second] = idp.requestsTo("/token");
			expect(first?.headers.get("authorization")).toBe(basic(idp.clientId, "first-secret"));
			expect(second?.headers.get("authorization")).toBe(basic(idp.clientId, "second-secret"));
		});

		it("private_key_jwt: the assertion verifies under the public key and names the client", async () => {
			const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
			const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
			const { idp, provider } = await build({
				clientSecret: undefined,
				privateKey: { pem, kid: "rp-key-1" },
			});
			idp.nonce = "nonce-1";
			await exchange(provider);
			const req = idp.lastTokenRequest();
			expect(req?.headers.get("authorization")).toBeNull();
			expect(req?.body?.get("client_assertion_type")).toBe(
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			);
			const assertion = req?.body?.get("client_assertion") ?? "";
			const { payload, protectedHeader } = await jwtVerify(assertion, publicKey, {
				issuer: idp.clientId,
				subject: idp.clientId,
				audience: ISSUER,
			});
			expect(protectedHeader).toMatchObject({ alg: "RS256", kid: "rp-key-1" });
			expect(typeof payload.jti).toBe("string");
		});

		it("infers ES256 for a P-256 key given as a bare PEM", async () => {
			const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
			const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
			const { idp, provider } = await build({ clientSecret: undefined, privateKey: pem });
			idp.nonce = "nonce-1";
			await exchange(provider);
			const assertion = idp.lastTokenRequest()?.body?.get("client_assertion") ?? "";
			const header = JSON.parse(Buffer.from(assertion.split(".")[0] ?? "", "base64url").toString());
			expect(header.alg).toBe("ES256");
		});

		it("refuses both credentials, and neither", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
			const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
			await expect(
				createOidcProvider("idp-a", baseConfig(idp, { privateKey: pem })),
			).rejects.toThrow(/clientSecret.*privateKey|privateKey.*clientSecret/);
			await expect(
				createOidcProvider("idp-a", baseConfig(idp, { clientSecret: undefined })),
			).rejects.toThrow(/clientSecret.*privateKey|privateKey.*clientSecret/);
		});
	});

	describe("authorization request", () => {
		it("carries PKCE S256, state, nonce, the scopes and the callback", async () => {
			const { idp, provider } = await build();
			const url = authorize(provider, "nonce-1");
			const q = url.searchParams;
			expect(q.get("response_type")).toBe("code");
			expect(q.get("client_id")).toBe(idp.clientId);
			expect(q.get("redirect_uri")).toBe(CALLBACK);
			expect(q.get("scope")).toBe("openid profile email");
			expect(q.get("state")).toBe("state-1");
			expect(q.get("nonce")).toBe("nonce-1");
			expect(q.get("code_challenge")).toBe(codeChallenge(VERIFIER));
			expect(q.get("code_challenge_method")).toBe("S256");
		});

		it("requests the configured scopes", async () => {
			const { provider } = await build({ scopes: ["openid", "email", "groups"] });
			expect(provider.scope).toEqual(["openid", "email", "groups"]);
			expect(authorize(provider, "n").searchParams.get("scope")).toBe("openid email groups");
		});

		it("refuses scopes without openid", async () => {
			const idp = await createFakeIdp({ issuer: ISSUER });
			await expect(
				createOidcProvider("idp-a", baseConfig(idp, { scopes: ["profile", "email"] })),
			).rejects.toThrow(/openid/);
		});

		it("refuses to build a request without a nonce", async () => {
			const { provider } = await build();
			expect(() => authorize(provider, undefined)).toThrow(/nonce/);
			expect(() => authorize(provider, "")).toThrow(/nonce/);
			await expect(
				provider.exchangeCode({ code: "code-1", codeVerifier: VERIFIER, redirectUri: CALLBACK }),
			).rejects.toThrow(/nonce/);
		});
	});

	describe("ID token conformance", () => {
		it("accepts a conforming token and maps the profile", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			const before = Date.now();
			const profile = await exchange(provider);

			expect(profile).toMatchObject({
				issuer: ISSUER,
				sub: idp.sub,
				email: "alice@example.test",
				emailVerified: true,
				name: "Alice Example",
				picture: `${ISSUER}/alice.png`,
				accessToken: "at-1",
				refreshToken: "rt-1",
			});
			expect(typeof profile.idToken).toBe("string");
			expect(profile.expiresAt?.getTime()).toBeGreaterThanOrEqual(before + 3600_000 - 1000);

			const token = idp.lastTokenRequest();
			expect(token?.body?.get("grant_type")).toBe("authorization_code");
			expect(token?.body?.get("code")).toBe("code-1");
			expect(token?.body?.get("code_verifier")).toBe(VERIFIER);
			expect(token?.body?.get("redirect_uri")).toBe(CALLBACK);

			const userinfo = idp.requestsTo("/userinfo");
			expect(userinfo).toHaveLength(1);
			expect(userinfo[0]?.headers.get("authorization")).toBe("Bearer at-1");
		});

		it("refuses a nonce that is not the transaction's, before any userinfo call", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-from-another-transaction";
			await expect(exchange(provider, "nonce-1")).rejects.toThrow();
			expect(idp.requestsTo("/userinfo")).toHaveLength(0);
		});

		it("refuses a token minted for another audience", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.idTokenClaims = { aud: "another-client" };
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("refuses an expired token", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			const now = Math.floor(Date.now() / 1000);
			idp.idTokenClaims = { iat: now - 600, exp: now - 120 };
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("refuses a token from another issuer", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.idTokenClaims = { iss: "https://impostor.test" };
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("refuses a token response without an id_token", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.omitIdToken = true;
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("picks up a rotated signing key once the cached JWKS is a minute old", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.setSystemTime(new Date("2026-09-11T00:00:00Z"));
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			await exchange(provider);
			expect(idp.requestsTo("/jwks")).toHaveLength(1);

			const rotated = await idp.rotateKey();
			expect(rotated).toBe("kid-2");
			// The key-selection guard refuses to refetch a JWKS it fetched less
			// than a minute ago — a token under a brand-new kid is refused until
			// the cache ages, which is why an IdP publishes a key before signing
			// with it.
			await expect(exchange(provider)).rejects.toThrow();
			expect(idp.requestsTo("/jwks")).toHaveLength(1);

			vi.setSystemTime(new Date("2026-09-11T00:01:01Z"));
			const profile = await exchange(provider);
			expect(profile.sub).toBe(idp.sub);
			expect(idp.requestsTo("/jwks")).toHaveLength(2);
		});

		it("refuses a kid no published key matches, even after refetching", async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.setSystemTime(new Date("2026-09-11T00:00:00Z"));
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			await exchange(provider);

			idp.signingKid = "kid-ghost";
			vi.setSystemTime(new Date("2026-09-11T00:01:01Z"));
			await expect(exchange(provider)).rejects.toThrow();
			expect(idp.requestsTo("/jwks")).toHaveLength(2);
			expect(idp.requestsTo("/userinfo")).toHaveLength(1);
		});

		it("checks at_hash against the access token when the id_token carries one", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.atHash = "valid";
			await expect(exchange(provider)).resolves.toMatchObject({ sub: idp.sub });

			idp.atHash = "wrong";
			await expect(exchange(provider)).rejects.toThrow(/at_hash/);
			expect(idp.requestsTo("/userinfo")).toHaveLength(1);
		});

		it("binds userinfo to the id_token sub", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.userinfoClaims = { sub: "someone-else" };
			await expect(exchange(provider)).rejects.toThrow();
		});

		it("userInfo = false: the profile comes from the id_token alone", async () => {
			const { idp, provider } = await build({ userInfo: false });
			idp.nonce = "nonce-1";
			const profile = await exchange(provider);
			expect(idp.requestsTo("/userinfo")).toHaveLength(0);
			expect(profile).toMatchObject({
				sub: idp.sub,
				email: "alice@example.test",
				name: "Alice Example",
			});
			expect(profile.picture).toBeUndefined();
		});

		it("skips userinfo when the issuer publishes no endpoint, and refuses userInfo = true then", async () => {
			const { idp, provider } = await build({}, { userinfo: false });
			idp.nonce = "nonce-1";
			const profile = await exchange(provider);
			expect(profile.sub).toBe(idp.sub);
			expect(idp.requestsTo("/userinfo")).toHaveLength(0);

			const strict = await createFakeIdp({ issuer: ISSUER, userinfo: false });
			await expect(
				createOidcProvider("idp-a", baseConfig(strict, { userInfo: true })),
			).rejects.toThrow(/userinfo_endpoint/);
		});

		it("normalises email_verified to a boolean, or drops it", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.userinfoClaims = { email_verified: "true" };
			expect((await exchange(provider)).emailVerified).toBe(true);
			idp.userinfoClaims = { email_verified: "false" };
			expect((await exchange(provider)).emailVerified).toBe(false);
			idp.userinfoClaims = { email_verified: 42 };
			expect((await exchange(provider)).emailVerified).toBeUndefined();
		});

		it("carries groups only as a string array", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			idp.userinfoClaims = { groups: ["admins", "devs"] };
			const profile = await exchange(provider);
			expect(profile.groups).toEqual(["admins", "devs"]);
			expect(provider.mapClaims(profile).groups).toEqual(["admins", "devs"]);

			idp.userinfoClaims = { groups: ["admins", 7] };
			expect((await exchange(provider)).groups).toBeUndefined();
		});
	});

	describe("refresh, logout and claim mapping", () => {
		it("refreshes through the token endpoint and returns the new snapshot", async () => {
			const { idp, provider } = await build();
			expect(supportsRefresh(provider)).toBe(true);
			const refreshed = await provider.refreshToken("rt-1");
			const req = idp.lastTokenRequest();
			expect(req?.body?.get("grant_type")).toBe("refresh_token");
			expect(req?.body?.get("refresh_token")).toBe("rt-1");
			expect(refreshed).toMatchObject({ accessToken: "at-refreshed", refreshToken: "rt-2" });
			expect(refreshed.expiresAt).toBeInstanceOf(Date);
		});

		it("offers RP-initiated logout only when the issuer publishes an end_session_endpoint", async () => {
			const { provider: plain } = await build();
			expect(supportsLogout(plain)).toBe(false);

			const { provider } = await build({}, { endSession: true });
			expect(supportsLogout(provider)).toBe(true);
			if (!supportsLogout(provider)) throw new Error("unreachable");
			const { url, method } = await provider.endSession({
				idTokenHint: "id-token",
				postLogoutRedirectUri: "https://app.test/bye",
				state: "st",
			});
			expect(method).toBe("GET");
			expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/logout`);
			expect(url.searchParams.get("id_token_hint")).toBe("id-token");
			expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://app.test/bye");
			expect(url.searchParams.get("state")).toBe("st");
		});

		it("maps the promotable claims and nothing else", async () => {
			const { idp, provider } = await build();
			idp.nonce = "nonce-1";
			const profile = await exchange(provider);
			const mapped = provider.mapClaims({ ...profile, accessToken: "leak", hd: "leak" });
			expect(mapped).toEqual({
				email: "alice@example.test",
				emailVerified: true,
				name: "Alice Example",
				picture: `${ISSUER}/alice.png`,
			});
		});
	});
});
