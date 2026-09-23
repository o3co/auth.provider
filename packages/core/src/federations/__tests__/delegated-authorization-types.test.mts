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
import type {
	DelegatedTokens,
	FederationGrantRefresher,
	FederationProfile,
	RefreshedTokens,
	SupportsDelegatedAuthorization,
} from "#/index.mjs";

/**
 * Type-level: what the capability answers is what core's retrieval consumes
 * (#593, D17), and the named fields of a token snapshot are checked — which
 * `Omit` over an index signature did not do.
 */
describe("delegated authorization types (#593, D17)", () => {
	it("an adapter with the capability is a refresher core can use, and its answer is what core reads", () => {
		const tokens: DelegatedTokens = {
			accessToken: "at",
			refreshToken: "rt",
			expiresIn: 3600,
			expiresAt: new Date(0),
			scope: "openid",
			tokenType: "bearer",
		};
		const rotationOnly: DelegatedTokens = { refreshToken: "rt-2" };
		// One type since #626 P1: what the capability answers with and what the
		// retrieval consumes were two identical declarations, and the assertions
		// that they agreed are now the identity itself.
		const adapter: SupportsDelegatedAuthorization = {
			buildDelegatedAuthorizationUrl: () => new URL("https://idp.test/authorize"),
			exchangeDelegatedCode: async () => ({
				upstream: { issuer: "https://idp.test", subject: "s", claims: {} },
				tokens,
			}),
			refreshDelegatedToken: async () => tokens,
		};
		const refresher: FederationGrantRefresher = adapter;
		expect(tokens.accessToken).toBe("at");
		expect(rotationOnly.refreshToken).toBe("rt-2");
		expect(typeof refresher.refreshDelegatedToken).toBe("function");
	});

	it("checks the named fields of a refreshed snapshot: a wrong type is an error, as it should always have been", () => {
		const snapshot: RefreshedTokens = {
			accessToken: "at",
			expiresAt: null,
			expiresIn: 1800,
			scope: "openid",
			tokenType: "bearer",
			vendorExtra: 42,
		};
		// @ts-expect-error an access token is a string
		const wrongAccessToken: RefreshedTokens = { accessToken: 42 };
		// @ts-expect-error `expiresIn` is seconds or null
		const wrongExpiresIn: RefreshedTokens = { expiresIn: "3600" };
		// @ts-expect-error `scope` is space-delimited, not a list
		const wrongScope: RefreshedTokens = { scope: ["openid"] };
		const profile: FederationProfile = {
			issuer: "https://idp.test",
			sub: "u1",
			expiresAt: null,
			expiresIn: null,
			tokenType: "bearer",
		};
		expect(snapshot.vendorExtra).toBe(42);
		expect(wrongAccessToken).toBeDefined();
		expect(wrongExpiresIn).toBeDefined();
		expect(wrongScope).toBeDefined();
		expect(profile.sub).toBe("u1");
	});
});
