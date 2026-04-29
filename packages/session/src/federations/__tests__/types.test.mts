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

import { describe, expect, it } from "vitest";
import {
	type FederationProfile,
	type FederationProvider,
	type SupportsClaimMapping,
	type SupportsLogout,
	type SupportsRefresh,
	supportsClaimMapping,
	supportsLogout,
	supportsRefresh,
} from "../types.mjs";

describe("FederationProvider type guards", () => {
	const minimalProvider: FederationProvider = {
		name: "test",
		scope: ["openid"],
		buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
		exchangeCode: async () => ({
			issuer: "https://example.com",
			sub: "u1",
		}),
	};

	it("supportsRefresh returns false for a provider lacking refreshToken", () => {
		expect(supportsRefresh(minimalProvider)).toBe(false);
		expect(supportsRefresh(null)).toBe(false);
		expect(supportsRefresh(undefined)).toBe(false);
	});

	it("supportsRefresh narrows when refreshToken is a function", () => {
		const p: FederationProvider & SupportsRefresh = {
			...minimalProvider,
			refreshToken: async () => ({
				issuer: "https://example.com",
				sub: "u1",
			}),
		};
		expect(supportsRefresh(p)).toBe(true);
	});

	it("supportsLogout returns false for a provider lacking endSession", () => {
		expect(supportsLogout(minimalProvider)).toBe(false);
	});

	it("supportsLogout narrows when endSession is a function", () => {
		const p: FederationProvider & SupportsLogout = {
			...minimalProvider,
			endSession: async () => ({ url: new URL("https://example.com/end"), method: "GET" as const }),
		};
		expect(supportsLogout(p)).toBe(true);
	});

	it("supportsClaimMapping returns false for a provider lacking mapClaims", () => {
		expect(supportsClaimMapping(minimalProvider)).toBe(false);
	});

	it("supportsClaimMapping narrows when mapClaims is a function", () => {
		const p: FederationProvider & SupportsClaimMapping = {
			...minimalProvider,
			mapClaims: () => ({}),
		};
		expect(supportsClaimMapping(p)).toBe(true);
	});
});

describe("FederationProfile shape", () => {
	it("allows OIDC-standard claims as first-class fields", () => {
		const profile: FederationProfile = {
			issuer: "https://example.com",
			sub: "u1",
			email: "a@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/p",
			accessToken: "at",
			refreshToken: "rt",
			idToken: "it",
			expiresAt: new Date(0),
		};
		expect(profile.sub).toBe("u1");
	});

	it("accepts provider-specific extension claims through the index signature", () => {
		const profile: FederationProfile = {
			issuer: "https://example.com",
			sub: "u1",
			expiresAt: null,
			hd: "example.com", // Google-specific hosted-domain claim
			tid: "tenant-id", // Microsoft-specific tenant id
		};
		expect(profile.hd).toBe("example.com");
		expect(profile.tid).toBe("tenant-id");
	});

	it("requires expiresAt (Date | null) — null signals no finite expiry", () => {
		// null path: GitHub OAuth Apps classic tokens have no finite expiry.
		const classic: FederationProfile = {
			issuer: "https://github.com",
			sub: "99",
			accessToken: "at",
			expiresAt: null,
		};
		expect(classic.expiresAt).toBeNull();

		// Date path: OIDC providers always return expires_in.
		const oidc: FederationProfile = {
			issuer: "https://accounts.google.com",
			sub: "gu1",
			accessToken: "at",
			expiresAt: new Date(0),
		};
		expect(oidc.expiresAt).toBeInstanceOf(Date);
	});
});
