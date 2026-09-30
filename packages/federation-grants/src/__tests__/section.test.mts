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
 * The schema of `federation-grants {}`, the federation-grants module's own
 * section (ADR 2026-09-17-federation-grants-offline-delegation): every key an
 * operator writes, each leaf read from the string a variable carries, strict
 * at every level. The real bounds are enforced where the values are used
 * (`resolveFederationGrantRetrievalLimits`, the acquisition settings); the
 * defaults live in the package's `config/reference.conf`. The grant stores'
 * own keys — their retention, their key ring — are their sections', and
 * refused here.
 */

import { describe, expect, it } from "vitest";
import { federationGrantsConfigSchema } from "#/module.mjs";

const parse = (section: unknown) => federationGrantsConfigSchema.parse(section);

describe("the federation-grants section", () => {
	it("keeps every key an operator set", () => {
		const written = {
			enabled: true,
			defaultExpiresIn: 1209600,
			maxExpiresIn: 2592000,
			refreshBuffer: 30,
			ineligibleRetryAfter: 300,
			refreshFailureBackoff: 30,
			upstreamTimeoutMs: 10000,
			upstreamHardTimeoutMs: 25000,
			refreshLockTtlMs: 30000,
			lockWaitMs: 5000,
			persistRetryBudgetMs: 3000,
			allowKeepOnSubjectRevocation: false,
			identityLookup: "unsupported",
			consent: { url: "/consent/grants" },
			connections: {
				graph: {
					federation: "entra",
					scopes: ["openid", "offline_access", "Files.Read"],
					resource: "https://graph.microsoft.com",
					boundary: "graph-2026-09",
					maxAccessTokenLifetime: 3600,
					allowScopeSubsets: true,
					authorizationParams: { prompt: "consent" },
					callbackURL: "https://app.example.test/grants/cb",
					// What check 5's Store matches a person on (federation-grants
					// ADR); check 5 asks the Store with them.
					identityClaims: ["oid", "tid"],
				},
			},
		};
		expect(parse(written)).toStrictEqual(written);
	});

	it("takes the booleans as the strings HOCON substitution leaves behind", () => {
		// `${?VAR}` arrives as a string, so a section that declared a plain
		// boolean would refuse every environment-driven deployment.
		expect(parse({ enabled: "true" })?.enabled).toBe(true);
		expect(parse({ enabled: "false" })?.enabled).toBe(false);
		expect(parse({ allowKeepOnSubjectRevocation: "true" })?.allowKeepOnSubjectRevocation).toBe(
			true,
		);
		expect(
			parse({
				connections: {
					graph: {
						federation: "entra",
						scopes: ["openid"],
						boundary: "b",
						maxAccessTokenLifetime: 3600,
						allowScopeSubsets: "false",
					},
				},
			})?.connections?.graph?.allowScopeSubsets,
		).toBe(false);
	});

	it("takes a decimal string, and refuses everything that is not one", () => {
		// HOCON substitutes `${?VAR}` as a string, always, so a plain decimal
		// is what an operator wrote.
		expect(parse({ maxExpiresIn: "2592000" })?.maxExpiresIn).toBe(2592000);
		expect(parse({ maxExpiresIn: " 2592000 " })?.maxExpiresIn).toBe(2592000);

		// And nothing else, unlike `z.coerce.number()`: `Number()` reads `null`
		// and `[]` as `0`, `true` as `1` and `"1e3"` as `1000`, which would
		// NORMALISE a malformed duration before the strict reader downstream —
		// which refuses exactly these — saw it. `refreshBuffer: null` would
		// hand out tokens with milliseconds left.
		for (const value of ["thirty", "", "1e3", "0x10", -1, 0, 1.5, null, true, false, [], [45]]) {
			expect(() => parse({ maxExpiresIn: value }), JSON.stringify(value)).toThrow();
		}
	});

	it("is absent when nothing declares it, and an empty section is valid", () => {
		expect(parse(undefined)).toBeUndefined();
		expect(parse({})).toStrictEqual({});
		// An operator who removed every connection has an empty map, not a
		// missing key: removing the last one must remain an operable change.
		expect(parse({ connections: {} })?.connections).toStrictEqual({});
	});

	it("keeps the vocabulary of the keys whose values are a closed set", () => {
		expect(parse({ identityLookup: "required" })?.identityLookup).toBe("required");
		expect(() => parse({ identityLookup: "optional" })).toThrow();
	});

	it("refuses a connection missing what has no sensible default", () => {
		// `federation`, `scopes`, `boundary` and `maxAccessTokenLifetime` have
		// none: a guessed access-token maximum would invent a residual-access
		// policy, and a guessed boundary would silently share one.
		const whole = {
			federation: "entra",
			scopes: ["openid"],
			boundary: "b",
			maxAccessTokenLifetime: 3600,
		};
		expect(() => parse({ connections: { graph: whole } })).not.toThrow();
		for (const missing of ["federation", "scopes", "boundary", "maxAccessTokenLifetime"]) {
			const partial: Record<string, unknown> = { ...whole };
			delete partial[missing];
			expect(() => parse({ connections: { graph: partial } }), missing).toThrow();
		}
	});

	it("refuses a key it does not declare, a grant store's among them, at every level", () => {
		for (const section of [
			{ tombstoneRetention: 60 },
			{ encryptionMode: "required" },
			{ encryptionKeys: [{ id: "k", key: "c2VjcmV0" }] },
			{ consent: { uri: "/consent" } },
			{
				connections: {
					graph: {
						federation: "entra",
						scopes: ["openid"],
						boundary: "b",
						maxAccessTokenLifetime: 3600,
						scope: ["openid"],
					},
				},
			},
		]) {
			expect(() => parse(section), JSON.stringify(section)).toThrow();
		}
	});
});
