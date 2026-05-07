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
		clientId: "client-id",
		clientSecret: "client-secret",
		callbackURL: "https://app.example.com/session/oauth/federation/github/callback",
		// IH-12: legacy registration default. Existing v0.5.0 tests run as OAuth Apps
		// (PKCE not enforced by GitHub). Each test that needs the github-app branch
		// constructs its own config explicitly.
		appKind: "oauth-app" as const,
	};

	beforeEach(() => {
		vi.resetAllMocks();
	});

	it("advertises name and GitHub scopes", () => {
		const p = createGithubProvider(baseConfig);
		expect(p.name).toBe("github");
		expect([...p.scope]).toEqual(["read:user", "user:email"]);
	});

	it("buildAuthorizationUrl forwards redirect_uri/state/code_challenge to openid-client with GitHub authorize URL (github-app branch)", () => {
		// IH-12: PKCE is only emitted on the github-app branch. baseConfig is "oauth-app"
		// (legacy default) so this test explicitly opts into github-app to exercise PKCE
		// forwarding. Dedicated oauth-app tests below assert that those params are absent.
		mockBuildAuthorizationUrl.mockReturnValueOnce(
			new URL("https://github.com/login/oauth/authorize?stub=1"),
		);
		const p = createGithubProvider({ ...baseConfig, appKind: "github-app" });
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
		// IH-12: this test exercises PKCE forwarding alongside the rest of the
		// composition contract, so opt explicitly into the github-app branch (oauth-app
		// strips pkceCodeVerifier; that branch is covered by the dedicated IH-12 RED
		// tests below).
		const p = createGithubProvider({ ...baseConfig, appKind: "github-app" });
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
		// expires_in: 28800 → expiresAt is a Date ~8h in the future
		expect(profile.expiresAt).toBeInstanceOf(Date);
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

	it("exchangeCode returns expiresAt=null when GitHub omits expires_in (OAuth Apps classic)", async () => {
		// GitHub OAuth Apps classic tokens have no finite expiry; the token response
		// omits expires_in entirely. Adapter MUST return `null` (not `undefined`) so
		// the FederationTokenStore envelope can distinguish "no expiry" from a missing
		// field, and /oauth/federation/:name/token refuses to refresh.
		mockAuthorizationCodeGrant.mockResolvedValueOnce({ access_token: "gh-classic" });
		mockFetchUserInfo.mockResolvedValueOnce({ id: 7, login: "carol" });
		mockFetchProtectedResource.mockResolvedValueOnce({ json: async () => [] });
		const p = createGithubProvider(baseConfig);
		const profile = await p.exchangeCode({
			code: "c",
			codeVerifier: "v",
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.expiresAt).toBeNull();
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

	// -----------------------------------------------------------------------
	// IH-12 — appKind discriminator + PKCE branching
	// -----------------------------------------------------------------------

	describe("IH-12: appKind discriminator + PKCE branching", () => {
		// IH-12 RED-1 — compile-time guard. `appKind` is a required field on
		// GithubProviderConfig with no default; omitting it must fail tsc. The
		// `@ts-expect-error` directive itself errors if the next line type-checks
		// successfully, so this is the runnable form of the spec's "config without
		// appKind → TypeScript error" assertion.
		it("appKind is required at the type level", () => {
			// @ts-expect-error appKind is required; omitting it must fail TypeScript.
			createGithubProvider({
				clientId: "id",
				clientSecret: "sec",
				callbackURL: "https://app.example.com/cb",
			});
			// Runtime: the omission compiles via the @ts-expect-error escape, and the
			// provider returns without throwing — the contract is enforced at the type
			// level, not at runtime, by design (matches the spec's explicit-choice goal).
		});

		// IH-12 RED-2 — oauth-app branch must NOT emit PKCE params. Pre-fix the route
		// always sends `code_challenge` + `code_challenge_method`, GitHub silently ignores
		// them, and consumers reading the auth URL get a misleading security signal that
		// PKCE is binding the request.
		it("oauth-app: buildAuthorizationUrl does not include code_challenge or code_challenge_method", () => {
			mockBuildAuthorizationUrl.mockReturnValueOnce(
				new URL("https://github.com/login/oauth/authorize?stub=1"),
			);
			const p = createGithubProvider({ ...baseConfig, appKind: "oauth-app" });
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "verifier-0123456789-abcdef",
			});
			const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [
				unknown,
				Record<string, unknown>,
			];
			expect(params.code_challenge).toBeUndefined();
			expect(params.code_challenge_method).toBeUndefined();
			// Sibling-fields that are NOT gated by appKind must still be present so the
			// strip is surgical, not a regression of the rest of the auth URL.
			expect(params.state).toBe("s");
			expect(params.redirect_uri).toBe(baseConfig.callbackURL);
		});

		// IH-12 RED-3 — github-app branch MUST emit PKCE params (positive guard;
		// complements the migrated existing test by asserting from the perspective of a
		// reviewer who lands on RED-2 first and needs to confirm the branch isn't
		// always-off).
		it("github-app: buildAuthorizationUrl includes code_challenge=<base64url> + code_challenge_method=S256", () => {
			mockBuildAuthorizationUrl.mockReturnValueOnce(
				new URL("https://github.com/login/oauth/authorize?stub=1"),
			);
			const p = createGithubProvider({ ...baseConfig, appKind: "github-app" });
			p.buildAuthorizationUrl({
				redirectUri: baseConfig.callbackURL,
				state: "s",
				codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			});
			const [, params] = mockBuildAuthorizationUrl.mock.calls[0] as [
				unknown,
				Record<string, string>,
			];
			expect(params.code_challenge_method).toBe("S256");
			expect(params.code_challenge).toMatch(/^[A-Za-z0-9_-]+$/);
		});

		// IH-12 RED-4 — oauth-app branch must NOT pass `pkceCodeVerifier` to the token
		// exchange. GitHub OAuth Apps ignore it, and including it muddies the upstream
		// library's idea of which flow is in use.
		it("oauth-app: exchangeCode omits pkceCodeVerifier from authorizationCodeGrant", async () => {
			mockAuthorizationCodeGrant.mockResolvedValueOnce({
				access_token: "gh-at",
				expires_in: 28800,
			});
			mockFetchUserInfo.mockResolvedValueOnce({
				id: 12345,
				login: "octocat",
				email: "octocat@example.com",
			});
			const p = createGithubProvider({ ...baseConfig, appKind: "oauth-app" });
			await p.exchangeCode({
				code: "auth-code",
				codeVerifier: "v",
				redirectUri: baseConfig.callbackURL,
			});
			const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
				unknown,
				unknown,
				Record<string, unknown>,
			];
			expect(checks).not.toHaveProperty("pkceCodeVerifier");
		});

		// IH-12 RED-5 — github-app branch MUST pass `pkceCodeVerifier` so openid-client
		// posts `code_verifier` to GitHub's token endpoint and the upstream PKCE check
		// runs.
		it("github-app: exchangeCode passes pkceCodeVerifier to authorizationCodeGrant", async () => {
			mockAuthorizationCodeGrant.mockResolvedValueOnce({
				access_token: "gh-at",
				expires_in: 28800,
			});
			mockFetchUserInfo.mockResolvedValueOnce({
				id: 12345,
				login: "octocat",
				email: "octocat@example.com",
			});
			const p = createGithubProvider({ ...baseConfig, appKind: "github-app" });
			await p.exchangeCode({
				code: "auth-code",
				codeVerifier: "my-verifier",
				redirectUri: baseConfig.callbackURL,
			});
			const [, , checks] = mockAuthorizationCodeGrant.mock.calls[0] as [
				unknown,
				unknown,
				{ pkceCodeVerifier?: string },
			];
			expect(checks.pkceCodeVerifier).toBe("my-verifier");
		});
	});
});
