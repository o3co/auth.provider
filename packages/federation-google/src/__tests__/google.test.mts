/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
	mockBuildAuthorizationUrl: vi.fn(),
	mockAuthorizationCodeGrant: vi.fn(),
	mockFetchUserInfo: vi.fn(),
	mockRefreshTokenGrant: vi.fn(),
	skipStateCheckSym: Symbol("skipStateCheck"),
	skipSubjectCheckSym: Symbol("skipSubjectCheck"),
}));
const {
	mockBuildAuthorizationUrl,
	mockAuthorizationCodeGrant,
	mockFetchUserInfo,
	mockRefreshTokenGrant,
	skipStateCheckSym,
	skipSubjectCheckSym,
} = hoisted;

vi.mock("openid-client", () => ({
	Configuration: class MockConfiguration {
		constructor(
			public serverMetadata: unknown,
			public clientId: string,
			public clientSecret?: string,
		) {}
	},
	buildAuthorizationUrl: (...args: unknown[]) => hoisted.mockBuildAuthorizationUrl(...args),
	authorizationCodeGrant: (...args: unknown[]) => hoisted.mockAuthorizationCodeGrant(...args),
	fetchUserInfo: (...args: unknown[]) => hoisted.mockFetchUserInfo(...args),
	refreshTokenGrant: (...args: unknown[]) => hoisted.mockRefreshTokenGrant(...args),
	skipStateCheck: hoisted.skipStateCheckSym,
	skipSubjectCheck: hoisted.skipSubjectCheckSym,
}));

import { createGoogleProvider } from "../google.mjs";
import { makeTestGoogleIdToken } from "./helpers.mjs";

describe("createGoogleProvider on openid-client", () => {
	const baseConfig = {
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: "https://app.example.com/session/oauth/federation/google/callback",
	};

	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("advertises name and OIDC scopes", () => {
		const p = createGoogleProvider(baseConfig);
		expect(p.name).toBe("google");
		expect([...p.scope]).toEqual(["openid", "profile", "email"]);
	});

	it("buildAuthorizationUrl forwards redirect_uri/state/code_challenge/access_type to openid-client", () => {
		mockBuildAuthorizationUrl.mockReturnValueOnce(
			new URL("https://accounts.google.com/o/oauth2/v2/auth?stub=1"),
		);
		const p = createGoogleProvider(baseConfig);
		const verifier = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";
		const url = p.buildAuthorizationUrl({
			redirectUri: baseConfig.callbackURL,
			state: "abc",
			codeVerifier: verifier,
		});
		expect(url.hostname).toBe("accounts.google.com");
		const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [unknown, Record<string, string>];
		expect(params.redirect_uri).toBe(baseConfig.callbackURL);
		expect(params.state).toBe("abc");
		expect(params.code_challenge_method).toBe("S256");
		expect(params.code_challenge).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(params.access_type).toBe("offline");
		expect(params.scope).toBe("openid profile email");
	});

	it("exchangeCode composes authorizationCodeGrant + fetchUserInfo into a FederationProfile", async () => {
		const { jwt, sub: idTokenSub } = await makeTestGoogleIdToken({ sub: "g-123" });
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			access_token: "at",
			refresh_token: "rt",
			id_token: jwt,
			expires_in: 3600,
			claims: () => ({
				sub: idTokenSub,
				iss: "https://accounts.google.com",
				aud: "client-id",
			}),
		});
		mockFetchUserInfo.mockResolvedValueOnce({
			sub: "g-123",
			email: "alice@example.com",
			email_verified: true,
			name: "Alice",
			picture: "https://example.com/p",
			hd: "example.com",
		});
		const p = createGoogleProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "auth-code",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.issuer).toBe("https://accounts.google.com");
		expect(profile.sub).toBe("g-123");
		expect(profile.email).toBe("alice@example.com");
		expect(profile.emailVerified).toBe(true);
		expect(profile.name).toBe("Alice");
		expect(profile.picture).toBe("https://example.com/p");
		expect(profile.accessToken).toBe("at");
		expect(profile.refreshToken).toBe("rt");
		expect(profile.idToken).toBe(jwt);
		expect(profile.expiresAt).toBeInstanceOf(Date);
		expect(profile.hd).toBe("example.com");
		const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
			unknown,
			unknown,
			{ pkceCodeVerifier: string; expectedState: symbol },
		];
		expect(checks.pkceCodeVerifier).toBe("v");
		expect(checks.expectedState).toBe(skipStateCheckSym);
	});

	it("refreshToken returns a RefreshedTokens snapshot without sub (caller preserves stored sub)", async () => {
		mockRefreshTokenGrant.mockResolvedValueOnce({
			access_token: "at2",
			refresh_token: "rt2",
			expires_in: 3600,
		});
		const p = createGoogleProvider(baseConfig);
		const refreshed = await p.refreshToken("old-refresh");
		expect(refreshed.accessToken).toBe("at2");
		expect(refreshed.refreshToken).toBe("rt2");
		expect(refreshed.expiresAt).toBeInstanceOf(Date);
		// `sub` / `issuer` are absent on purpose — RefreshedTokens makes them optional.
		expect(refreshed.sub).toBeUndefined();
	});

	it("mapClaims maps first-class + extension claims (no raw access)", () => {
		const p = createGoogleProvider(baseConfig);
		const claims = p.mapClaims({
			issuer: "https://accounts.google.com",
			sub: "g-123",
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/p",
			hd: "example.com",
		});
		expect(claims.email).toBe("alice@example.com");
		expect(claims.emailVerified).toBe(true);
		expect(claims.name).toBe("Alice");
		expect(claims.picture).toBe("https://example.com/p");
		expect(claims.hd).toBe("example.com");
	});

	// -----------------------------------------------------------------------
	// PB-4 — Google federation OIDC compliance (nonce, jwks_uri, alg pin)
	// -----------------------------------------------------------------------

	describe("PB-4: id_token verification + nonce binding", () => {
		// PB-4 RED-1: jwks_uri + alg pin in serverMetadata
		// Pre-fix: serverMetadata has neither jwks_uri nor id_token_signing_alg_values_supported,
		// so openid-client cannot verify the RS256 signature. Post-fix: both are present and the
		// alg list is locked to RS256 (no `none`/`HS256` confusion).
		it("constructs serverMetadata with Google's jwks_uri and RS256 alg pin", async () => {
			type CapturedMetadata = {
				jwks_uri?: unknown;
				id_token_signing_alg_values_supported?: unknown;
			};
			let captured: CapturedMetadata | undefined;
			mockBuildAuthorizationUrl.mockImplementationOnce((cfg: unknown) => {
				captured = (cfg as { serverMetadata: CapturedMetadata }).serverMetadata;
				return new URL("https://accounts.google.com/o/oauth2/v2/auth?stub=1");
			});
			const p = createGoogleProvider(baseConfig);
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "v",
			});
			expect(captured).toBeDefined();
			const sm = captured as CapturedMetadata;
			expect(sm.jwks_uri).toBe("https://www.googleapis.com/oauth2/v3/certs");
			expect(sm.id_token_signing_alg_values_supported).toEqual(["RS256"]);
		});

		// PB-4 RED-2: jwksUri config override is honored
		it("honours config.jwksUri override (test injection)", () => {
			type CapturedMetadata = { jwks_uri?: unknown };
			let captured: CapturedMetadata | undefined;
			mockBuildAuthorizationUrl.mockImplementationOnce((cfg: unknown) => {
				captured = (cfg as { serverMetadata: CapturedMetadata }).serverMetadata;
				return new URL("https://accounts.google.com/o/oauth2/v2/auth?stub=1");
			});
			const p = createGoogleProvider({
				...baseConfig,
				jwksUri: "https://test.example.com/jwks.json",
			});
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "v",
			});
			expect(captured).toBeDefined();
			expect((captured as CapturedMetadata).jwks_uri).toBe("https://test.example.com/jwks.json");
		});

		// PB-4 RED-3: buildAuthorizationUrl forwards nonce to upstream when supplied
		it("forwards nonce param to oidc.buildAuthorizationUrl when present", () => {
			mockBuildAuthorizationUrl.mockReturnValueOnce(
				new URL("https://accounts.google.com/o/oauth2/v2/auth?stub=1"),
			);
			const p = createGoogleProvider(baseConfig);
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "v",
				nonce: "session-nonce-abcdef",
			});
			const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [
				unknown,
				Record<string, string>,
			];
			expect(params.nonce).toBe("session-nonce-abcdef");
		});

		// PB-4 RED-4: omits nonce when caller does not supply one (backward-compat for OAuth providers)
		it("does not include nonce in upstream params when caller omits it", () => {
			mockBuildAuthorizationUrl.mockReturnValueOnce(
				new URL("https://accounts.google.com/o/oauth2/v2/auth?stub=1"),
			);
			const p = createGoogleProvider(baseConfig);
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "v",
			});
			const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [
				unknown,
				Record<string, string>,
			];
			expect(params.nonce).toBeUndefined();
		});

		// PB-4 RED-5: exchangeCode threads nonce → expectedNonce (TD-9 M2 pattern: inspect checks
		// argument so the test is RED for the right reason — pre-fix `checks.expectedNonce` is
		// `undefined`, the mock rejects; post-fix it equals the provided nonce, the mock resolves.)
		it("threads nonce param into oidc.authorizationCodeGrant as expectedNonce", async () => {
			const { jwt, sub: idTokenSub } = await makeTestGoogleIdToken({ nonce: "session-n" });
			mockAuthorizationCodeGrant.mockImplementationOnce(
				(_cfg: unknown, _url: unknown, checks: { expectedNonce?: string }) => {
					if (checks.expectedNonce !== "session-n") {
						return Promise.reject(new Error("nonce mismatch / expectedNonce missing"));
					}
					return Promise.resolve({
						access_token: "at",
						refresh_token: "rt",
						id_token: jwt,
						expires_in: 3600,
						claims: () => ({ sub: idTokenSub, iss: "https://accounts.google.com" }),
					});
				},
			);
			mockFetchUserInfo.mockResolvedValueOnce({ sub: idTokenSub });
			const p = createGoogleProvider(baseConfig);
			const profile = await p.exchangeCode({
				code: "c",
				codeVerifier: "v",
				redirectUri: baseConfig.callbackURL,
				nonce: "session-n",
			});
			expect(profile.sub).toBe(idTokenSub);
			const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
				unknown,
				unknown,
				{ expectedNonce?: string },
			];
			expect(checks.expectedNonce).toBe("session-n");
		});

		// PB-4 RED-6: Pre-fix RED guard. With the route now passing nonce, callers that *forget*
		// to pass it will hit `checks.expectedNonce === undefined`, which openid-client treats as
		// "expect no nonce in id_token" — letting any nonce-claim-bearing token slip through. The
		// mock here mimics openid-client's real failure semantics for the NULL case so the test
		// fails for the right reason.
		it("rejects when caller omits nonce for OIDC provider (id_token would not be bound)", async () => {
			mockAuthorizationCodeGrant.mockImplementationOnce(
				(_cfg: unknown, _url: unknown, checks: { expectedNonce?: string }) => {
					if (!checks.expectedNonce) {
						return Promise.reject(new Error("expectedNonce required"));
					}
					return Promise.resolve({
						access_token: "at",
						id_token: "it",
						expires_in: 3600,
						claims: () => ({ sub: "x" }),
					});
				},
			);
			const p = createGoogleProvider(baseConfig);
			await expect(
				p.exchangeCode({
					code: "c",
					codeVerifier: "v",
					redirectUri: baseConfig.callbackURL,
					// nonce intentionally omitted
				}),
			).rejects.toThrow(/expectedNonce/);
		});
	});

	// -----------------------------------------------------------------------
	// PB-5 — UserInfo sub binding (OIDC §5.3.2)
	// -----------------------------------------------------------------------

	describe("PB-5: UserInfo sub binding against id_token sub", () => {
		// PB-5 RED-1: when id_token has a sub, the route passes that sub (not skipSubjectCheck)
		// as expectedSubject to fetchUserInfo. openid-client compares it against UserInfo.sub
		// and throws on mismatch.
		it("binds UserInfo to id_token sub when id_token claims include sub", async () => {
			const { jwt, sub: idTokenSub } = await makeTestGoogleIdToken({ sub: "id-tok-user" });
			mockAuthorizationCodeGrant.mockResolvedValueOnce({
				access_token: "at",
				id_token: jwt,
				expires_in: 3600,
				claims: () => ({ sub: idTokenSub, iss: "https://accounts.google.com" }),
			});
			mockFetchUserInfo.mockResolvedValueOnce({ sub: idTokenSub });
			const p = createGoogleProvider(baseConfig);
			await p.exchangeCode({
				code: "c",
				codeVerifier: "v",
				redirectUri: baseConfig.callbackURL,
				nonce: "n",
			});
			const [, , expectedSubject] = mockFetchUserInfo.mock.calls[0] as [unknown, unknown, unknown];
			expect(expectedSubject).toBe(idTokenSub);
			// Critically NOT the skipSubjectCheck symbol: PB-5 fix replaces the unconditional
			// skip with the bound id_token sub on the OIDC happy path.
			expect(expectedSubject).not.toBe(skipSubjectCheckSym);
		});

		// PB-5 RED-2: when id_token claims have no sub (degenerate / non-OIDC tokens), fall back
		// to skipSubjectCheck. This preserves the OAuth-only path's behavior.
		it("falls back to skipSubjectCheck when id_token claims lack sub", async () => {
			mockAuthorizationCodeGrant.mockResolvedValueOnce({
				access_token: "at",
				id_token: "it",
				expires_in: 3600,
				claims: () => undefined,
			});
			mockFetchUserInfo.mockResolvedValueOnce({ sub: "any" });
			const p = createGoogleProvider(baseConfig);
			await p.exchangeCode({
				code: "c",
				codeVerifier: "v",
				redirectUri: baseConfig.callbackURL,
				nonce: "n",
			});
			const [, , expectedSubject] = mockFetchUserInfo.mock.calls[0] as [unknown, unknown, unknown];
			expect(expectedSubject).toBe(skipSubjectCheckSym);
		});

		// PB-5 RED-3: a UserInfo response with a sub mismatched against id_token's sub must
		// surface as an exchangeCode failure (openid-client throws `RPError` in production;
		// the mock simulates that contract here).
		it("rejects when fetchUserInfo throws (UserInfo sub mismatch)", async () => {
			const { jwt, sub: idTokenSub } = await makeTestGoogleIdToken({ sub: "id-sub" });
			mockAuthorizationCodeGrant.mockResolvedValueOnce({
				access_token: "at",
				id_token: jwt,
				expires_in: 3600,
				claims: () => ({ sub: idTokenSub }),
			});
			mockFetchUserInfo.mockRejectedValueOnce(
				new Error("UserInfo sub mismatch (expected id-sub, got attacker)"),
			);
			const p = createGoogleProvider(baseConfig);
			await expect(
				p.exchangeCode({
					code: "c",
					codeVerifier: "v",
					redirectUri: baseConfig.callbackURL,
					nonce: "n",
				}),
			).rejects.toThrow(/UserInfo sub mismatch/);
		});
	});
});
