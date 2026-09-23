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
	identityClaimsProblem,
	RESERVED_IDENTITY_CLAIMS,
	type SupportsClaimMapping,
	type SupportsDelegatedAuthorization,
	type SupportsLogout,
	type SupportsRefresh,
	selectIdentityClaims,
	supportsClaimMapping,
	supportsDelegatedAuthorization,
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
			expiresAt: null,
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

	it("supportsDelegatedAuthorization needs ALL THREE methods: an adapter written against the earlier pair does not have it", () => {
		expect(supportsDelegatedAuthorization(minimalProvider)).toBe(false);
		expect(supportsDelegatedAuthorization(null)).toBe(false);
		expect(supportsDelegatedAuthorization(undefined)).toBe(false);
		const methods = {
			buildDelegatedAuthorizationUrl: () => new URL("https://example.com/authorize"),
			exchangeDelegatedCode: async () => ({
				upstream: { issuer: "https://example.com", subject: "s", claims: {} },
				tokens: {},
			}),
			refreshDelegatedToken: async () => ({}),
		};
		// Every subset of two — including the pair slice 2 shipped, which is what
		// a custom adapter written before slice 6 has.
		for (const missing of Object.keys(methods) as (keyof typeof methods)[]) {
			const { [missing]: _dropped, ...rest } = methods;
			const partial: FederationProvider & Partial<SupportsDelegatedAuthorization> = {
				...minimalProvider,
				...rest,
			};
			expect(supportsDelegatedAuthorization(partial), `without ${missing}`).toBe(false);
		}
	});

	it("supportsDelegatedAuthorization narrows when all three are functions", () => {
		const p: FederationProvider & SupportsDelegatedAuthorization = {
			...minimalProvider,
			buildDelegatedAuthorizationUrl: () => new URL("https://example.com/authorize"),
			exchangeDelegatedCode: async () => ({
				upstream: { issuer: "https://example.com", subject: "s", claims: {} },
				tokens: { refreshToken: "rt-1" },
			}),
			refreshDelegatedToken: async () => ({ refreshToken: "rt-2" }),
		};
		expect(supportsDelegatedAuthorization(p)).toBe(true);
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

describe("identity claims (#611)", () => {
	it("accepts printable names, and an empty list", () => {
		expect(identityClaimsProblem([])).toBeUndefined();
		expect(
			identityClaimsProblem(["oid", "tid", "https://example.test/claims/employee"]),
		).toBeUndefined();
	});

	it("refuses a reserved, malformed, non-string or repeated name, by name", () => {
		for (const name of RESERVED_IDENTITY_CLAIMS) {
			expect(identityClaimsProblem([name]), name).toMatch(new RegExp(`"${name}"`));
		}
		for (const bad of ["", "a b", "tab\t", "é", "x".repeat(257), 7, null]) {
			expect(identityClaimsProblem([bad]), String(bad)).toMatch(/not a claim name/);
		}
		expect(identityClaimsProblem(["oid", "oid"])).toMatch(/twice/);
	});

	it("selects own, non-empty string claims only, into a fresh object", () => {
		const claims = Object.assign(Object.create({ inherited: "from-prototype" }), {
			oid: "O",
			tid: 42,
			empty: "",
			list: ["x"],
		}) as Record<string, unknown>;
		const selected = selectIdentityClaims(claims, [
			"oid",
			"tid",
			"empty",
			"list",
			"inherited",
			"absent",
		]);
		expect(selected).toEqual({ oid: "O" });
		expect(selected).not.toBe(claims);
		expect(selectIdentityClaims(claims, [])).toEqual({});
	});
});
