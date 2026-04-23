/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { createFederationProviderFactory } from "@o3co/auth-provider-session";
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

import { createGoogleProvider, registerGoogleFederation } from "../google.mjs";

describe("createGoogleProvider on openid-client", () => {
	const baseConfig = {
		name: "google",
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

	it("registerGoogleFederation registers the google factory type", async () => {
		const factory = createFederationProviderFactory();
		registerGoogleFederation(factory);

		const p = await factory.create({ type: "google", ...baseConfig });

		expect(factory.registeredTypes()).toEqual(["google"]);
		expect(p.name).toBe("google");
	});

	it("registerGoogleFederation throws when required builder fields are missing", async () => {
		const factory = createFederationProviderFactory();
		registerGoogleFederation(factory);

		await expect(factory.create({ type: "google", name: "google" })).rejects.toThrow(
			/clientId|clientSecret|callbackURL/i,
		);
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
		mockAuthorizationCodeGrant.mockResolvedValueOnce({
			access_token: "at",
			refresh_token: "rt",
			id_token: "it",
			expires_in: 3600,
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
		expect(profile.idToken).toBe("it");
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
});
