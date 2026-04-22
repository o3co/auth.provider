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
	mockFetchProtectedResource: vi.fn(),
	skipStateCheckSym: Symbol("skipStateCheck"),
	skipSubjectCheckSym: Symbol("skipSubjectCheck"),
}));
const {
	mockBuildAuthorizationUrl,
	mockAuthorizationCodeGrant,
	mockFetchUserInfo,
	mockFetchProtectedResource,
	skipStateCheckSym,
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
	fetchProtectedResource: (...args: unknown[]) => hoisted.mockFetchProtectedResource(...args),
	skipStateCheck: hoisted.skipStateCheckSym,
	skipSubjectCheck: hoisted.skipSubjectCheckSym,
}));

import { createGithubProvider } from "../github.mjs";

describe("createGithubProvider on openid-client", () => {
	const baseConfig = {
		name: "github",
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: "https://app.example.com/session/oauth/federation/github/callback",
	};

	beforeEach(() => {
		vi.resetAllMocks();
	});

	it("advertises name and GitHub scopes", () => {
		const p = createGithubProvider(baseConfig);
		expect(p.name).toBe("github");
		expect([...p.scope]).toEqual(["read:user", "user:email"]);
	});

	it("buildAuthorizationUrl forwards redirect_uri/state/code_challenge to openid-client with GitHub authorize URL", () => {
		mockBuildAuthorizationUrl.mockReturnValueOnce(
			new URL("https://github.com/login/oauth/authorize?stub=1"),
		);
		const p = createGithubProvider(baseConfig);
		const verifier = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";
		const url = p.buildAuthorizationUrl({
			redirectUri: baseConfig.callbackURL,
			state: "abc",
			codeVerifier: verifier,
		});
		expect(url.hostname).toBe("github.com");
		const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [unknown, Record<string, string>];
		expect(params.redirect_uri).toBe(baseConfig.callbackURL);
		expect(params.state).toBe("abc");
		expect(params.code_challenge_method).toBe("S256");
		expect(params.code_challenge).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(params.scope).toBe("read:user user:email");
	});

	it("exchangeCode composes authorizationCodeGrant + fetchUserInfo + /user/emails into a FederationProfile", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			access_token: "gh-at",
			expires_in: 28800,
		});
		// GitHub's /user returns `id: number`, not `sub` — real shape, no fiction.
		mockFetchUserInfo.mockResolvedValueOnce({
			id: 12345678,
			login: "alice",
			name: "Alice",
			avatar_url: "https://github.com/alice.png",
		});
		// /user/emails response: primary+verified email
		mockFetchProtectedResource.mockResolvedValueOnce({
			json: async () => [
				{ email: "alice@work.com", primary: true, verified: true },
				{ email: "alice@personal.com", primary: false, verified: true },
			],
		});
		const p = createGithubProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "gh-code",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.issuer).toBe("https://github.com");
		// Adapter must coerce numeric id → string sub.
		expect(profile.sub).toBe("12345678");
		expect(profile.email).toBe("alice@work.com");
		expect(profile.emailVerified).toBe(true);
		expect(profile.name).toBe("Alice");
		// GitHub returns avatar_url, not picture — adapter maps avatar_url → picture.
		expect(profile.picture).toBe("https://github.com/alice.png");
		expect(profile.accessToken).toBe("gh-at");
		// GitHub OAuth Apps do not issue refresh tokens
		expect(profile.refreshToken).toBeUndefined();
		const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
			unknown,
			unknown,
			{ pkceCodeVerifier: string; expectedState: symbol },
		];
		expect(checks.pkceCodeVerifier).toBe("v");
		expect(checks.expectedState).toBe(skipStateCheckSym);
	});

	it("exchangeCode coerces numeric GitHub id to string sub (C-1 regression guard)", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({ access_token: "gh-tok" });
		// Real GitHub shape: id is a number, no sub field at all.
		mockFetchUserInfo.mockResolvedValueOnce({ id: 99, login: "bob" });
		mockFetchProtectedResource.mockResolvedValueOnce({
			json: async () => [],
		});
		const p = createGithubProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "c",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.sub).toBe("99");
		expect(typeof profile.sub).toBe("string");
	});

	it("exchangeCode throws a descriptive error when userinfo has neither id nor sub", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({ access_token: "gh-tok2" });
		// No id, no sub — should never happen in production but must be caught.
		mockFetchUserInfo.mockResolvedValueOnce({ login: "nosub" });
		mockFetchProtectedResource.mockResolvedValueOnce({
			json: async () => [],
		});
		const p = createGithubProvider(baseConfig);
		await expect(
			p.exchangeCode({ code: "c", codeVerifier: "v", redirectUri: baseConfig.callbackURL }),
		).rejects.toThrow(/without id\/sub/i);
	});

	it("exchangeCode falls back to first-verified email when primary email is unverified", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({ access_token: "gh-at2" });
		mockFetchUserInfo.mockResolvedValueOnce({ id: 99, login: "bob" });
		mockFetchProtectedResource.mockResolvedValueOnce({
			json: async () => [
				{ email: "unverified@example.com", primary: true, verified: false },
				{ email: "verified@example.com", primary: false, verified: true },
			],
		});
		const p = createGithubProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "c",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.email).toBe("verified@example.com");
		expect(profile.emailVerified).toBe(true);
	});

	it("exchangeCode sets email=undefined when no verified email exists", async () => {
		mockAuthorizationCodeGrant.mockResolvedValueOnce({ access_token: "gh-at3" });
		mockFetchUserInfo.mockResolvedValueOnce({ id: 77, login: "charlie" });
		mockFetchProtectedResource.mockResolvedValueOnce({
			json: async () => [{ email: "nope@example.com", primary: true, verified: false }],
		});
		const p = createGithubProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "c",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.email).toBeUndefined();
		expect(profile.emailVerified).toBeUndefined();
	});

	it("does NOT implement SupportsRefresh (GitHub OAuth Apps do not issue refresh tokens)", () => {
		const p = createGithubProvider(baseConfig);
		expect((p as Record<string, unknown>).refreshToken).toBeUndefined();
	});

	it("mapClaims maps first-class claims from FederationProfile", () => {
		const p = createGithubProvider(baseConfig);
		const claims = p.mapClaims({
			issuer: "https://github.com",
			sub: "12345678",
			email: "bob@work.com",
			emailVerified: true,
			name: "Bob",
			picture: "https://avatars.githubusercontent.com/u/12345678",
		});
		expect(claims.email).toBe("bob@work.com");
		expect(claims.emailVerified).toBe(true);
		expect(claims.name).toBe("Bob");
		expect(claims.picture).toBe("https://avatars.githubusercontent.com/u/12345678");
	});

	it("endSession redirects to postLogoutRedirectUri (GitHub has no end-session endpoint)", async () => {
		const p = createGithubProvider(baseConfig);
		const { url, method } = await p.endSession({
			postLogoutRedirectUri: "https://rp/done",
			state: "s1",
		});
		expect(method).toBe("GET");
		expect(url.href).toContain("https://rp/done");
		expect(url.searchParams.get("state")).toBe("s1");
	});

	it("endSession throws a descriptive error when postLogoutRedirectUri is an invalid URL", async () => {
		const p = createGithubProvider(baseConfig);
		await expect(p.endSession({ postLogoutRedirectUri: "not a valid url" })).rejects.toThrow(
			/invalid postLogoutRedirectUri/i,
		);
	});

	it("endSession honors configured endSessionEndpoint when present (I-1 — GitHub Enterprise support)", async () => {
		const p = createGithubProvider({
			...baseConfig,
			endSessionEndpoint: "https://github.example.corp/logout",
		});
		const { url, method } = await p.endSession({
			idTokenHint: "id-tok",
			postLogoutRedirectUri: "https://app.example.com/done",
			state: "st2",
		});
		expect(method).toBe("GET");
		expect(url.origin + url.pathname).toBe("https://github.example.corp/logout");
		expect(url.searchParams.get("id_token_hint")).toBe("id-tok");
		expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://app.example.com/done");
		expect(url.searchParams.get("state")).toBe("st2");
	});

	it("endSession falls back to https://github.com/logout when neither endSessionEndpoint nor postLogoutRedirectUri is set", async () => {
		const p = createGithubProvider(baseConfig);
		const { url, method } = await p.endSession({});
		expect(method).toBe("GET");
		expect(url.href).toContain("https://github.com/logout");
	});
});
