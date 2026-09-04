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

import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
	mockBuildAuthorizationUrl: vi.fn(),
	mockAuthorizationCodeGrant: vi.fn(),
	mockRefreshTokenGrant: vi.fn(),
	mockClientSecretPost: vi.fn((secret?: string) => ({ auth: "client_secret_post", secret })),
	skipStateCheckSym: Symbol("skipStateCheck"),
	skipSubjectCheckSym: Symbol("skipSubjectCheck"),
	configurations: [] as Array<{ serverMetadata: unknown; clientId: string; metadata: unknown }>,
}));

vi.mock("openid-client", () => ({
	Configuration: class MockConfiguration {
		constructor(
			public serverMetadata: unknown,
			public clientId: string,
			public metadata?: unknown,
			public clientAuthentication?: unknown,
		) {
			hoisted.configurations.push({ serverMetadata, clientId, metadata });
		}
	},
	buildAuthorizationUrl: (...args: unknown[]) => hoisted.mockBuildAuthorizationUrl(...args),
	authorizationCodeGrant: (...args: unknown[]) => hoisted.mockAuthorizationCodeGrant(...args),
	refreshTokenGrant: (...args: unknown[]) => hoisted.mockRefreshTokenGrant(...args),
	ClientSecretPost: (...args: [string?]) => hoisted.mockClientSecretPost(...args),
	skipStateCheck: hoisted.skipStateCheckSym,
	skipSubjectCheck: hoisted.skipSubjectCheckSym,
}));

const {
	mockBuildAuthorizationUrl,
	mockAuthorizationCodeGrant,
	mockRefreshTokenGrant,
	mockClientSecretPost,
	skipStateCheckSym,
} = hoisted;

import {
	APPLE_ISSUER,
	APPLE_PRIVATE_RELAY_DOMAIN,
	createAppleProvider,
	isPrivateRelayEmail,
} from "#/apple.mjs";
import { makeTestAppleIdToken, makeTestSigningKey } from "./helpers.mjs";

const CALLBACK_URL = "https://app.example.com/session/oauth/federation/apple/callback";

const baseConfig = {
	clientId: "com.example.app.service",
	clientSecret: "static-apple-secret",
	callbackURL: CALLBACK_URL,
};

const APPLE_SUB = "000123.7f4c1b9e0a2d4f8b93c1a6d5e0f27b41.0456";

/** The token response openid-client hands back, with Apple-shaped id_token claims. */
function appleTokenResponse(claims: Record<string, unknown> = {}) {
	return {
		access_token: "apple-access-token",
		refresh_token: "apple-refresh-token",
		id_token: "apple.id.token",
		expires_in: 3600,
		claims: () => ({
			iss: APPLE_ISSUER,
			aud: baseConfig.clientId,
			sub: APPLE_SUB,
			email: `sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`,
			email_verified: "true",
			is_private_email: "true",
			...claims,
		}),
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	hoisted.configurations.length = 0;
});

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

describe("createAppleProvider — construction", () => {
	it("advertises the name, Apple's scopes, and form_post response mode", () => {
		const p = createAppleProvider(baseConfig);
		expect(p.name).toBe("apple");
		expect([...p.scope]).toEqual(["name", "email"]);
		// Requesting `name` or `email` is exactly what makes Apple POST the
		// callback, so the two declarations belong to one another.
		expect(p.responseMode).toBe("form_post");
	});

	it("requires clientId and callbackURL", () => {
		expect(() => createAppleProvider({ ...baseConfig, clientId: "" })).toThrow(/clientId/);
		expect(() => createAppleProvider({ ...baseConfig, callbackURL: "" })).toThrow(/callbackURL/);
	});

	it("refuses a non-https callbackURL, which Apple would reject anyway", () => {
		expect(() =>
			createAppleProvider({ ...baseConfig, callbackURL: "http://localhost:3000/cb" }),
		).toThrow(/https/i);
	});

	it("accepts a static clientSecret", () => {
		expect(() => createAppleProvider(baseConfig)).not.toThrow();
	});

	it("accepts a clientSecret resolver", () => {
		expect(() =>
			createAppleProvider({ ...baseConfig, clientSecret: async () => "computed" }),
		).not.toThrow();
	});

	it("builds its own ES256 signer from teamId + keyId + privateKey", async () => {
		const key = await makeTestSigningKey();
		expect(() =>
			createAppleProvider({
				clientId: baseConfig.clientId,
				callbackURL: CALLBACK_URL,
				teamId: "ABCDE12345",
				keyId: "XYZW98765F",
				privateKey: key.privateKeyPem,
			}),
		).not.toThrow();
	});

	it("refuses both a clientSecret and raw key material — one source, not two", async () => {
		const key = await makeTestSigningKey();
		expect(() =>
			createAppleProvider({
				...baseConfig,
				teamId: "ABCDE12345",
				keyId: "XYZW98765F",
				privateKey: key.privateKeyPem,
			}),
		).toThrow(/either .*clientSecret.* or/i);
	});

	it("refuses neither — no secret at all is a boot-time misconfiguration", () => {
		expect(() =>
			createAppleProvider({ clientId: baseConfig.clientId, callbackURL: CALLBACK_URL }),
		).toThrow(/clientSecret/);
	});

	it("refuses partial key material rather than signing with a hole in it", async () => {
		const key = await makeTestSigningKey();
		expect(() =>
			createAppleProvider({
				clientId: baseConfig.clientId,
				callbackURL: CALLBACK_URL,
				teamId: "ABCDE12345",
				privateKey: key.privateKeyPem,
			}),
		).toThrow(/keyId/);
	});
});

// ---------------------------------------------------------------------------
// Authorization request
// ---------------------------------------------------------------------------

describe("buildAuthorizationUrl", () => {
	it("forwards redirect_uri / state / PKCE / nonce / scope to openid-client", () => {
		mockBuildAuthorizationUrl.mockReturnValueOnce(
			new URL("https://appleid.apple.com/auth/authorize?stub=1"),
		);
		const p = createAppleProvider(baseConfig);
		const url = p.buildAuthorizationUrl({
			redirectUri: CALLBACK_URL,
			state: "state-abc",
			codeVerifier: "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef",
			nonce: "nonce-abc",
		});
		expect(url.hostname).toBe("appleid.apple.com");
		const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [unknown, Record<string, string>];
		expect(params.redirect_uri).toBe(CALLBACK_URL);
		expect(params.state).toBe("state-abc");
		expect(params.scope).toBe("name email");
		expect(params.code_challenge_method).toBe("S256");
		expect(params.code_challenge).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(params.nonce).toBe("nonce-abc");
	});

	it("fails closed without a nonce — Apple is OIDC and the id_token must bind", () => {
		const p = createAppleProvider(baseConfig);
		expect(() =>
			p.buildAuthorizationUrl({
				redirectUri: CALLBACK_URL,
				state: "s",
				codeVerifier: "v",
			}),
		).toThrow(/nonce/i);
	});

	it("does not resolve the client secret to build a URL that needs none", () => {
		mockBuildAuthorizationUrl.mockReturnValueOnce(
			new URL("https://appleid.apple.com/auth/authorize"),
		);
		const clientSecret = vi.fn(() => "computed");
		const p = createAppleProvider({ ...baseConfig, clientSecret });
		p.buildAuthorizationUrl({
			redirectUri: CALLBACK_URL,
			state: "s",
			codeVerifier: "v",
			nonce: "n",
		});
		expect(clientSecret).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

describe("exchangeCode", () => {
	const exchangeArgs = {
		code: "apple-authorization-code",
		codeVerifier: "verifier",
		redirectUri: CALLBACK_URL,
		nonce: "nonce-abc",
	};

	it("builds a FederationProfile from the id_token claims alone (Apple has no userinfo)", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode(exchangeArgs);

		expect(profile.issuer).toBe(APPLE_ISSUER);
		expect(profile.sub).toBe(APPLE_SUB);
		expect(profile.email).toBe(`sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`);
		expect(profile.accessToken).toBe("apple-access-token");
		expect(profile.refreshToken).toBe("apple-refresh-token");
		expect(profile.idToken).toBe("apple.id.token");
		expect(profile.expiresAt).toBeInstanceOf(Date);

		const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
			unknown,
			URL,
			{ pkceCodeVerifier: string; expectedState: symbol; expectedNonce: string },
		];
		expect(checks.pkceCodeVerifier).toBe("verifier");
		expect(checks.expectedState).toBe(skipStateCheckSym);
		expect(checks.expectedNonce).toBe("nonce-abc");
	});

	it("carries Apple's signed id_token through to the profile verbatim", async () => {
		const { jwt, claims } = await makeTestAppleIdToken({ sub: APPLE_SUB });
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			access_token: "at",
			id_token: jwt,
			expires_in: 3600,
			claims: () => claims,
		});
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode(exchangeArgs);
		expect(profile.idToken).toBe(jwt);
		expect(profile.sub).toBe(APPLE_SUB);
		// The fixture's `email_verified` is the string "true", as Apple sends it.
		expect(profile.emailVerified).toBe(true);
		// Apple issues no refresh token on every response; absence stays absence.
		expect(profile.refreshToken).toBeUndefined();
	});

	it("normalises a string email_verified to a boolean", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ email_verified: "true" }),
		);
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).emailVerified).toBe(true);
	});

	it('normalises the string "false" to false, not to truthiness', async () => {
		// The whole reason the normalisation exists: `Boolean("false")` is `true`,
		// and this claim gates nothing less than whether an address is verified.
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ email_verified: "false" }),
		);
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).emailVerified).toBe(false);
	});

	it("accepts a boolean email_verified unchanged", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse({ email_verified: true }));
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).emailVerified).toBe(true);
	});

	it("leaves emailVerified absent when the claim is absent — absence is not `false`", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ email_verified: undefined }),
		);
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).emailVerified).toBeUndefined();
	});

	it("surfaces is_private_email as isPrivateEmail so a deployment can decide about relays", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ is_private_email: "true" }),
		);
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).isPrivateEmail).toBe(true);
	});

	it("falls back to the relay domain when Apple omits is_private_email", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ is_private_email: undefined }),
		);
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).isPrivateEmail).toBe(true);
	});

	it("reports a real address as not private", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({
				email: "ada@example.com",
				is_private_email: "false",
			}),
		);
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode(exchangeArgs);
		expect(profile.isPrivateEmail).toBe(false);
		expect(profile.email).toBe("ada@example.com");
	});

	it("takes the display name from the first authorization's `user` body", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode({
			...exchangeArgs,
			callbackParams: {
				user: JSON.stringify({
					name: { firstName: "Ada", lastName: "Lovelace" },
					email: "ada@example.com",
				}),
			},
		});
		expect(profile.name).toBe("Ada Lovelace");
		// The id_token's email stays authoritative: it is signed, the body is not.
		expect(profile.email).toBe(`sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`);
	});

	it("handles a user body with only one name part", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode({
			...exchangeArgs,
			callbackParams: { user: JSON.stringify({ name: { firstName: "Ada" } }) },
		});
		expect(profile.name).toBe("Ada");
	});

	it("leaves name absent on a later authorization, where Apple sends no user body", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		expect((await p.exchangeCode(exchangeArgs)).name).toBeUndefined();
	});

	it("ignores a malformed user body rather than failing a valid login", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode({
			...exchangeArgs,
			callbackParams: { user: "{not json" },
		});
		expect(profile.name).toBeUndefined();
		expect(profile.sub).toBe(APPLE_SUB);
	});

	it("ignores a user body whose name is not the documented shape", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode({
			...exchangeArgs,
			callbackParams: { user: JSON.stringify({ name: "Ada Lovelace" }) },
		});
		expect(profile.name).toBeUndefined();
	});

	it("fails closed without a nonce", async () => {
		const p = createAppleProvider(baseConfig);
		await expect(p.exchangeCode({ ...exchangeArgs, nonce: undefined })).rejects.toThrow(/nonce/i);
	});

	it("fails closed when the token response exposes no claims at all", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			access_token: "at",
			expires_in: 3600,
			claims: () => undefined,
		});
		const p = createAppleProvider(baseConfig);
		await expect(p.exchangeCode(exchangeArgs)).rejects.toThrow(/sub/i);
	});

	it("falls back to a one-hour expiry when Apple sends no expires_in", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			...appleTokenResponse(),
			expires_in: undefined,
		});
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode(exchangeArgs);
		const seconds = Math.round(((profile.expiresAt as Date).getTime() - Date.now()) / 1000);
		expect(seconds).toBeGreaterThan(3500);
		expect(seconds).toBeLessThanOrEqual(3600);
	});

	it("leaves isPrivateEmail absent when there is neither a marker nor an email to judge", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(
			appleTokenResponse({ email: undefined, is_private_email: undefined }),
		);
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode(exchangeArgs);
		expect(profile.email).toBeUndefined();
		expect(profile.isPrivateEmail).toBeUndefined();
	});

	it.each([
		["a JSON scalar", "123"],
		["a JSON null", "null"],
		["an empty string", ""],
		["a name object with no usable parts", JSON.stringify({ name: { firstName: "" } })],
	])("ignores a user body that is %s", async (_label, user) => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse());
		const p = createAppleProvider(baseConfig);
		const profile = await p.exchangeCode({ ...exchangeArgs, callbackParams: { user } });
		expect(profile.name).toBeUndefined();
	});

	it("fails closed when the id_token carries no sub", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce(appleTokenResponse({ sub: undefined }));
		const p = createAppleProvider(baseConfig);
		await expect(p.exchangeCode(exchangeArgs)).rejects.toThrow(/sub/i);
	});

	it("resolves the client secret per exchange and posts it as client_secret_post", async () => {
		mockAuthorizationCodeGrant.mockResolvedValue(appleTokenResponse());
		const clientSecret = vi
			.fn()
			.mockResolvedValueOnce("secret-1")
			.mockResolvedValueOnce("secret-2");
		const p = createAppleProvider({ ...baseConfig, clientSecret });

		await p.exchangeCode(exchangeArgs);
		await p.exchangeCode(exchangeArgs);

		// Two exchanges, two resolutions: a rotating secret must not be frozen
		// into the Configuration at construction time.
		expect(clientSecret).toHaveBeenCalledTimes(2);
		expect(mockClientSecretPost).toHaveBeenNthCalledWith(1, "secret-1");
		expect(mockClientSecretPost).toHaveBeenNthCalledWith(2, "secret-2");
	});

	it("propagates a client-secret resolver failure instead of calling the token endpoint", async () => {
		const p = createAppleProvider({
			...baseConfig,
			clientSecret: () => {
				throw new Error("p8 unreadable");
			},
		});
		await expect(p.exchangeCode(exchangeArgs)).rejects.toThrow("p8 unreadable");
		expect(mockAuthorizationCodeGrant).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

describe("refreshToken", () => {
	it("returns a RefreshedTokens snapshot without re-asserting identity", async () => {
		mockRefreshTokenGrant.mockResolvedValueOnce({
			access_token: "at2",
			refresh_token: "rt2",
			expires_in: 3600,
		});
		const p = createAppleProvider(baseConfig);
		const refreshed = await p.refreshToken("old-refresh");
		expect(refreshed.accessToken).toBe("at2");
		expect(refreshed.refreshToken).toBe("rt2");
		expect(refreshed.expiresAt).toBeInstanceOf(Date);
		expect(refreshed.sub).toBeUndefined();
	});

	it("resolves the client secret for the refresh grant too", async () => {
		mockRefreshTokenGrant.mockResolvedValueOnce({ access_token: "at2", expires_in: 3600 });
		const clientSecret = vi.fn(async () => "refresh-secret");
		const p = createAppleProvider({ ...baseConfig, clientSecret });
		await p.refreshToken("old-refresh");
		expect(clientSecret).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// Claim mapping
// ---------------------------------------------------------------------------

describe("mapClaims", () => {
	it("maps the claims Apple can assert, and only those", () => {
		const p = createAppleProvider(baseConfig);
		const claims = p.mapClaims({
			issuer: APPLE_ISSUER,
			sub: APPLE_SUB,
			email: `sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`,
			emailVerified: true,
			name: "Ada Lovelace",
			isPrivateEmail: true,
			expiresAt: null,
		});
		expect(claims).toEqual({
			email: `sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`,
			emailVerified: true,
			name: "Ada Lovelace",
			isPrivateEmail: true,
		});
	});

	it("produces the same claim names Google's module does, so promotion behaves alike", () => {
		const p = createAppleProvider(baseConfig);
		const claims = p.mapClaims({
			issuer: APPLE_ISSUER,
			sub: APPLE_SUB,
			email: "ada@example.com",
			name: "Ada",
			expiresAt: null,
		});
		// `email` and `name` are the promotable spellings from
		// PROMOTABLE_FEDERATED_CLAIMS; anything else stays namespaced.
		expect(Object.keys(claims).sort()).toEqual(["email", "name"]);
	});

	it("omits what the profile did not assert rather than writing undefined", () => {
		const p = createAppleProvider(baseConfig);
		const claims = p.mapClaims({ issuer: APPLE_ISSUER, sub: APPLE_SUB, expiresAt: null });
		expect(claims).toEqual({});
	});

	it("never maps an authorization-bearing claim, whatever the profile carries", () => {
		const p = createAppleProvider(baseConfig);
		const claims = p.mapClaims({
			issuer: APPLE_ISSUER,
			sub: APPLE_SUB,
			groups: ["admin"],
			roles: ["root"],
			expiresAt: null,
		});
		expect(claims.groups).toBeUndefined();
		expect(claims.roles).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

describe("endSession", () => {
	it("uses a configured endSessionEndpoint when the deployment supplies one", async () => {
		const p = createAppleProvider({
			...baseConfig,
			endSessionEndpoint: "https://idp.example.com/logout",
		});
		const { url, method } = await p.endSession({
			idTokenHint: "id-token",
			postLogoutRedirectUri: "https://app.example.com/",
			state: "st",
		});
		expect(method).toBe("GET");
		expect(url.origin).toBe("https://idp.example.com");
		expect(url.searchParams.get("id_token_hint")).toBe("id-token");
		expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://app.example.com/");
		expect(url.searchParams.get("state")).toBe("st");
	});

	it("redirects straight to postLogoutRedirectUri — Apple publishes no end_session_endpoint", async () => {
		const p = createAppleProvider(baseConfig);
		const { url } = await p.endSession({
			postLogoutRedirectUri: "https://app.example.com/goodbye",
			state: "st",
		});
		expect(url.href.startsWith("https://app.example.com/goodbye")).toBe(true);
		expect(url.searchParams.get("state")).toBe("st");
	});

	it("says so plainly when there is nowhere to send the user", async () => {
		// Google can fall back to accounts.google.com/Logout; Apple has no
		// equivalent URL at all, so an unanswerable request is an error rather
		// than a redirect to somewhere invented.
		const p = createAppleProvider(baseConfig);
		await expect(p.endSession({})).rejects.toThrow(/end_session_endpoint|postLogoutRedirectUri/);
	});

	it("rejects an invalid postLogoutRedirectUri rather than redirecting to it", async () => {
		const p = createAppleProvider(baseConfig);
		await expect(p.endSession({ postLogoutRedirectUri: "not a url" })).rejects.toThrow(
			/postLogoutRedirectUri/,
		);
	});

	it("rejects an invalid configured endpoint", async () => {
		const p = createAppleProvider({ ...baseConfig, endSessionEndpoint: "not a url" });
		await expect(p.endSession({})).rejects.toThrow(/endSessionEndpoint/);
	});
});

// ---------------------------------------------------------------------------
// Relay addresses
// ---------------------------------------------------------------------------

describe("isPrivateRelayEmail", () => {
	it("recognises Apple's relay domain, case-insensitively", () => {
		expect(isPrivateRelayEmail(`sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`)).toBe(true);
		expect(isPrivateRelayEmail("SXYZ@PrivateRelay.AppleID.com")).toBe(true);
	});

	it("does not match a lookalike domain", () => {
		expect(isPrivateRelayEmail("a@privaterelay.appleid.com.evil.example")).toBe(false);
		expect(isPrivateRelayEmail("a@notprivaterelay.appleid.com")).toBe(false);
		expect(isPrivateRelayEmail("ada@example.com")).toBe(false);
		expect(isPrivateRelayEmail("no-at-sign")).toBe(false);
	});
});
