/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * `createGithubProvider` against the real openid-client and a fake GitHub
 * (`fake-github.mts`): the authorization request, the code exchange, the
 * e-mail choice, the scope translation, `expiresAt`, logout and `mapClaims`.
 * How `/user` becomes the profile's `sub` is `github.user.test.mts`.
 *
 * Nothing here mocks the library. A stubbed openid-client once let every case
 * pass while no real GitHub login could: the stub handed back a `/user` body
 * the real library refuses.
 */

import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createGithubProvider } from "../github.mjs";
import {
	ACCESS_TOKEN,
	createFakeGithub,
	type FakeGithub,
	GITHUB,
	githubTokenResponse,
	githubUser,
} from "./fake-github.mjs";

const baseConfig = {
	clientId: "client-id",
	clientSecret: "client-secret",
	callbackURL: "https://app.example.com/session/oauth/federation/github/callback",
};
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";

let github: FakeGithub;

beforeEach(() => {
	github = createFakeGithub();
	vi.stubGlobal("fetch", github.fetch);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

const exchange = (extra: Record<string, unknown> = {}) => {
	const p = createGithubProvider(baseConfig);
	return p.exchangeCode({
		code: "gh-code",
		codeVerifier: VERIFIER,
		redirectUri: baseConfig.callbackURL,
		...extra,
	} as Parameters<typeof p.exchangeCode>[0]);
};

describe("createGithubProvider", () => {
	it("advertises name and GitHub scopes", () => {
		const p = createGithubProvider(baseConfig);
		expect(p.name).toBe("github");
		expect([...p.scope]).toEqual(["read:user", "user:email"]);
	});

	it("builds GitHub's authorization request with the requested scope and a PKCE S256 challenge", () => {
		const p = createGithubProvider(baseConfig);
		const url = p.buildAuthorizationUrl({
			redirectUri: baseConfig.callbackURL,
			state: "abc",
			codeVerifier: VERIFIER,
		});
		expect(`${url.origin}${url.pathname}`).toBe(GITHUB.authorizationEndpoint);
		expect(url.searchParams.get("client_id")).toBe("client-id");
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("redirect_uri")).toBe(baseConfig.callbackURL);
		expect(url.searchParams.get("state")).toBe("abc");
		expect(url.searchParams.get("scope")).toBe("read:user user:email");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("code_challenge")).toBe(
			createHash("sha256").update(VERIFIER).digest("base64url"),
		);
		// GitHub issues no id_token for a nonce to bind to.
		expect(url.searchParams.has("nonce")).toBe(false);
	});

	it("exchanges the code at GitHub's token endpoint with the PKCE verifier and the secret in the body", async () => {
		await exchange();
		const [tokenRequest] = github.requestsTo(GITHUB.tokenEndpoint);
		expect(tokenRequest?.method).toBe("POST");
		const body = tokenRequest?.body;
		expect(body?.get("grant_type")).toBe("authorization_code");
		expect(body?.get("code")).toBe("gh-code");
		expect(body?.get("code_verifier")).toBe(VERIFIER);
		expect(body?.get("redirect_uri")).toBe(baseConfig.callbackURL);
		// client_secret_post, openid-client's default for a client with a secret.
		expect(body?.get("client_id")).toBe("client-id");
		expect(body?.get("client_secret")).toBe("client-secret");
		expect(tokenRequest?.headers.has("authorization")).toBe(false);
	});

	it("#597: a callback's iss does not reach the library — the login succeeds and the token request carries only the grant's parameters (#598)", async () => {
		// GitHub names its issuer "https://github.com/login/oauth"; the library
		// is configured with the profile label "https://github.com". Forwarded,
		// the library would compare the two and refuse the login.
		const iss = "https://github.com/login/oauth";
		const profile = await exchange({ callbackParams: { iss, state: "route-checked" } });
		expect(profile.sub).toBe("12345");

		// The token request carries the route's code, the callback URL as
		// `redirect_uri`, and the grant's own parameters — nothing else.
		const [token] = github.requestsTo(GITHUB.tokenEndpoint);
		expect(token?.body?.get("code")).toBe("gh-code");
		expect(token?.body?.get("redirect_uri")).toBe(baseConfig.callbackURL);
		expect([...(token?.body?.keys() ?? [])].sort()).toEqual([
			"client_id",
			"client_secret",
			"code",
			"code_verifier",
			"grant_type",
			"redirect_uri",
		]);
		// No state is compared here: the route compared it against the session
		// before calling the adapter, and hands the adapter none. An adapter that
		// asked the library to expect one would refuse this login ("state"
		// missing), so the success above is the check that it does not.
	});

	it("fails the exchange when GitHub refuses the code, which it answers with HTTP 200 and an error body", async () => {
		github.token.body = {
			error: "bad_verification_code",
			error_description: "The code passed is incorrect or expired.",
			error_uri: "https://docs.github.com/apps/troubleshooting",
		};
		await expect(exchange()).rejects.toThrow();
		expect(github.requestsTo(GITHUB.user)).toHaveLength(0);
	});

	it("composes the token response, /user and /user/emails into a FederationProfile", async () => {
		const profile = await exchange();
		expect(profile.issuer).toBe("https://github.com");
		expect(profile.sub).toBe("12345");
		expect(profile.email).toBe("octocat@github.com");
		expect(profile.emailVerified).toBe(true);
		expect(profile.name).toBe("The Octocat");
		// GitHub returns avatar_url, not picture.
		expect(profile.picture).toBe("https://avatars.githubusercontent.com/u/12345?v=4");
		expect(profile.accessToken).toBe(ACCESS_TOKEN);
		expect(profile.refreshToken).toBeUndefined();
		expect(profile.scope).toBe("read:user user:email");
		const [emailsRequest] = github.requestsTo(GITHUB.emails);
		expect(emailsRequest?.headers.get("authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
	});

	it("returns expiresAt=null when GitHub omits expires_in (OAuth App tokens)", async () => {
		// `null`, not `undefined`: the FederationTokenStore envelope must tell
		// "no expiry" from a missing field, and /oauth/federation/:name/token
		// then reuses the token instead of refreshing it.
		const profile = await exchange();
		expect(profile.expiresAt).toBeNull();
	});

	it("returns expiresAt from expires_in, and still no refresh token, for an expiring user token", async () => {
		github.token.body = {
			...githubTokenResponse(),
			expires_in: 28800,
			refresh_token: "ghr_1B4a2e77838347a7E420ce178F2E7c6912E1692",
			refresh_token_expires_in: 15811200,
		};
		const before = Date.now();
		const profile = await exchange();
		expect(profile.expiresAt).toBeInstanceOf(Date);
		const at = (profile.expiresAt as Date).getTime();
		expect(at).toBeGreaterThanOrEqual(before + 28800 * 1000);
		expect(at).toBeLessThanOrEqual(Date.now() + 28800 * 1000);
		expect(profile.refreshToken).toBeUndefined();
	});

	it.each([
		["comma-delimited, as GitHub sends it", "read:user,user:email", "read:user user:email"],
		["with spaces after the commas", "read:user, user:email", "read:user user:email"],
		["a single scope", "read:user", "read:user"],
		["repeated", "read:user,read:user", "read:user"],
	])(
		"answers a space-delimited granted scope when GitHub sends it %s (#647)",
		async (_label, answered, expected) => {
			// RFC 6749 section 3.3 makes a scope a SPACE-delimited list, and GitHub
			// answers with commas. Passed through as it arrives, the whole string
			// reads as one scope everywhere downstream, and a client asking whether
			// `user:email` was granted is told no.
			github.token.body = { ...githubTokenResponse(), scope: answered };
			expect((await exchange()).scope).toBe(expected);
		},
	);

	it.each([
		["whitespace only", "  "],
		["a lone comma", ","],
	])(
		"keeps an answer that names nothing distinguishable from no answer: %s (#647)",
		async (_label, answered) => {
			// Normalised to the empty string rather than to `undefined`: the route
			// reads an ABSENT scope as "as requested", so flattening a present
			// answer into absence would record every requested scope as consent on
			// a response that granted none.
			github.token.body = { ...githubTokenResponse(), scope: answered };
			expect((await exchange()).scope).toBe("");
		},
	);

	it("answers undefined only when GitHub sends no scope field at all (#647)", async () => {
		const { scope: _scope, ...withoutScope } = githubTokenResponse();
		github.token.body = withoutScope;
		expect((await exchange()).scope).toBeUndefined();
	});

	it("fails the exchange when GitHub's scope is not a string — openid-client refuses it", async () => {
		github.token.body = { ...githubTokenResponse(), scope: ["read:user", "user:email"] };
		await expect(exchange()).rejects.toThrow();
	});

	it("falls back to the first verified e-mail when the primary one is unverified", async () => {
		github.emails.body = [
			{ email: "unverified@example.com", primary: true, verified: false },
			{ email: "verified@example.com", primary: false, verified: true },
		];
		const profile = await exchange();
		expect(profile.email).toBe("verified@example.com");
		expect(profile.emailVerified).toBe(true);
	});

	it.each([
		["null", null],
		["a string", "octocat@github.com"],
		["a number", 42],
		["an array", [{ email: "octocat@github.com", primary: true, verified: true }]],
	])(
		"skips a /user/emails row that is %s instead of losing the address beside it",
		async (_label, row) => {
			github.emails.body = [row, { email: "octocat@github.com", primary: true, verified: true }];
			const profile = await exchange();
			expect(profile.email).toBe("octocat@github.com");
			expect(profile.emailVerified).toBe(true);
		},
	);

	it("leaves the e-mail absent when no address is verified — and never takes /user's", async () => {
		github.user.body = { ...githubUser(), email: "public@example.com" };
		github.emails.body = [{ email: "nope@example.com", primary: true, verified: false }];
		const profile = await exchange();
		expect(profile.email).toBeUndefined();
		expect(profile.emailVerified).toBeUndefined();
	});

	it.each([
		["answers HTTP 403", { status: 403, body: { message: "Resource not accessible" } }],
		["answers HTTP 500", { status: 500, body: { message: "Server Error" } }],
		["is not JSON", { status: 200, raw: "<html></html>", contentType: "text/html" }],
		["is not an array", { status: 200, body: { message: "unexpected" } }],
	])(
		"signs in without an e-mail when /user/emails %s — and never falls back to /user's",
		async (_label, answer: Partial<FakeGithub["emails"]>) => {
			github.user.body = { ...githubUser(), email: "public@example.com" };
			Object.assign(github.emails, answer);
			const profile = await exchange();
			expect(profile.sub).toBe("12345");
			expect(profile.email).toBeUndefined();
			expect(profile.emailVerified).toBeUndefined();
		},
	);

	it("releases the body of a /user/emails that answers non-2xx instead of leaving it unread", async () => {
		github.emails.status = 500;
		github.emails.body = { message: "Server Error" };
		await exchange();
		const [emails] = github.requestsTo(GITHUB.emails);
		expect(emails?.response.bodyUsed).toBe(true);
	});

	it("asks /user and /user/emails for GitHub's JSON media type at REST API version 2022-11-28", async () => {
		// The `sub` rule reads `id` as GitHub's 2022-11-28 schema types it; the
		// version header pins that contract instead of taking GitHub's default.
		await exchange();
		for (const endpoint of [GITHUB.user, GITHUB.emails]) {
			const [request] = github.requestsTo(endpoint);
			expect(request?.headers.get("accept")).toBe("application/vnd.github+json");
			expect(request?.headers.get("x-github-api-version")).toBe("2022-11-28");
			expect(request?.headers.get("authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
		}
	});

	it("does NOT implement SupportsRefresh (GitHub OAuth Apps do not issue refresh tokens)", () => {
		const p = createGithubProvider(baseConfig);
		expect((p as unknown as Record<string, unknown>).refreshToken).toBeUndefined();
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
			expiresAt: null,
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

describe("config.fetch — a proxy, or a test seam", () => {
	it("sends the token request, /user and /user/emails through the configured fetch, never the global one", async () => {
		// A deployment behind an egress proxy hands the adapter the fetch that
		// reaches GitHub; the Google, Apple and OIDC adapters already take one.
		const refused: string[] = [];
		vi.stubGlobal("fetch", async (input: string | URL | Request) => {
			refused.push(String(input instanceof Request ? input.url : input));
			throw new Error("the global fetch must not be reached");
		});
		const own = createFakeGithub();
		const profile = await createGithubProvider({ ...baseConfig, fetch: own.fetch }).exchangeCode({
			code: "gh-code",
			codeVerifier: VERIFIER,
			redirectUri: baseConfig.callbackURL,
		});
		expect(profile.sub).toBe("12345");
		expect(refused).toEqual([]);
		expect(own.requests.map((r) => r.url.pathname)).toEqual([
			"/login/oauth/access_token",
			"/user",
			"/user/emails",
		]);
	});
});
