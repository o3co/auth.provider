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

/**
 * What Apple's `mapClaims` produces, run through the *real*
 * `mergeFederatedClaims` from `@o3co/auth-provider-session`.
 *
 * `apple.test.mts` asserts the claim names in isolation; this asserts the
 * consequence — that those names land where #279 says they should, without
 * this package restating the promotion rules or being trusted to have guessed
 * them right.
 */

import {
	FEDERATED_CLAIMS_KEY,
	mergeFederatedClaims,
	PROMOTABLE_FEDERATED_CLAIMS,
} from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { APPLE_ISSUER, APPLE_PRIVATE_RELAY_DOMAIN, createAppleProvider } from "#/apple.mjs";

const provider = createAppleProvider({
	clientId: "com.example.app.service",
	clientSecret: "secret",
	callbackURL: "https://app.example.com/session/oauth/federation/apple/callback",
});

const appleProfile = (overrides: Record<string, unknown> = {}) => ({
	issuer: APPLE_ISSUER,
	sub: "000123.7f4c1b9e0a2d4f8b93c1a6d5e0f27b41.0456",
	email: `sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`,
	emailVerified: true,
	name: "Ada Lovelace",
	isPrivateEmail: true,
	expiresAt: null,
	...overrides,
});

describe("Apple claims under the session package's precedence rules", () => {
	it("promotes email and name into the envelope when the local record is silent", () => {
		const claims = mergeFederatedClaims({
			localClaims: {},
			providerName: "apple",
			mappedClaims: provider.mapClaims(appleProfile()),
		});
		expect(claims.email).toBe(`sxyz@${APPLE_PRIVATE_RELAY_DOMAIN}`);
		expect(claims.name).toBe("Ada Lovelace");
	});

	it("maps only claim names the framework can promote or namespace", () => {
		const mapped = provider.mapClaims(appleProfile());
		for (const key of Object.keys(mapped)) {
			expect(["email", "emailVerified", "name", "isPrivateEmail"]).toContain(key);
		}
		// The two Apple can actually contribute to the top-level envelope are
		// both in the framework's promotable set; `picture` it never has.
		expect(PROMOTABLE_FEDERATED_CLAIMS).toContain("email");
		expect(PROMOTABLE_FEDERATED_CLAIMS).toContain("name");
	});

	it("leaves the local record's email and name untouched", () => {
		const claims = mergeFederatedClaims({
			localClaims: { email: "ada@corp.example", name: "Ada C." },
			providerName: "apple",
			mappedClaims: provider.mapClaims(appleProfile()),
		});
		expect(claims.email).toBe("ada@corp.example");
		expect(claims.name).toBe("Ada C.");
	});

	it("namespaces emailVerified and isPrivateEmail rather than promoting them", () => {
		const claims = mergeFederatedClaims({
			localClaims: {},
			providerName: "apple",
			mappedClaims: provider.mapClaims(appleProfile()),
		});
		// `emailVerified` is Store-owned since #297; `isPrivateEmail` is an Apple
		// extension. Both are recorded, neither is authoritative here.
		expect(claims.emailVerified).toBeUndefined();
		expect(claims.isPrivateEmail).toBeUndefined();
		const federated = claims[FEDERATED_CLAIMS_KEY] as Record<string, Record<string, unknown>>;
		expect(federated.apple.emailVerified).toBe(true);
		expect(federated.apple.isPrivateEmail).toBe(true);
	});

	it("records a relay address so a deployment can act on it without guessing", () => {
		// A relay address forwards mail and can be disabled by the user at any
		// time; the deployment decides whether that is acceptable, and this is
		// the value it reads to decide.
		const claims = mergeFederatedClaims({
			localClaims: {},
			providerName: "apple",
			mappedClaims: provider.mapClaims(appleProfile({ isPrivateEmail: false })),
		});
		const federated = claims[FEDERATED_CLAIMS_KEY] as Record<string, Record<string, unknown>>;
		expect(federated.apple.isPrivateEmail).toBe(false);
	});

	it("writes no federated namespace at all for a profile that asserted nothing", () => {
		const claims = mergeFederatedClaims({
			localClaims: {},
			providerName: "apple",
			mappedClaims: provider.mapClaims({ issuer: APPLE_ISSUER, sub: "s", expiresAt: null }),
		});
		expect(claims[FEDERATED_CLAIMS_KEY]).toBeUndefined();
	});
});
