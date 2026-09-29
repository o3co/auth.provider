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

// The `federationGrants` configuration block (ADR
// 2026-09-17-federation-grants-offline-delegation), declared in core rather
// than in the route package: this schema strips keys it does not know and the
// standalone validates against it before any module's `configSchema` runs,
// and the Redis grant store, installed whether or not the routes are, reads
// the same block.
//
// Presence-and-shape only, but for the one-year ceiling on the tombstone
// retention, which the stores are handed directly. The real bounds are
// enforced where the values are used (`assertFederationGrantRetrievalLimits`,
// the store's constructor); the defaults live in `config/reference.conf`.

import { describe, expect, it } from "vitest";
import { fullSectionsSchema } from "#/config/application.schema.mjs";

/**
 * What an operator writes, after HOCON has turned `${?VAR}` into strings.
 *
 * Picked out of `fullSectionsSchema` rather than parsed beside every other
 * section: what is being checked is that the key is DECLARED there — an
 * undeclared one is stripped — and the section's own shape.
 */
const section = fullSectionsSchema.pick({ federationGrants: true });
const parse = (federationGrants: unknown) =>
	section.parse({ federationGrants } as never).federationGrants;

describe("the federationGrants section (#593)", () => {
	it("survives the pre-parse with every key an operator set", () => {
		// The failure this guards against is silent: an undeclared block is
		// stripped, the module sees defaults, and an operator's encryption keys
		// or lifetime bound are simply not there.
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
			tombstoneRetention: 2592000,
			encryptionMode: "required",
			encryptionKeys: [{ id: "k-2026-09", key: "c2VjcmV0" }],
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
					// ADR). Undeclared in the connection's value schema it would be
					// stripped here, and check 5 would ask the Store with no
					// evidence at all.
					identityClaims: ["oid", "tid"],
				},
			},
		};
		expect(parse(written)).toStrictEqual(written);
	});

	it("takes the booleans as the strings HOCON substitution leaves behind (#288)", () => {
		// `${?VAR}` arrives as a string, so a section that declared a plain
		// boolean would refuse every environment-driven deployment.
		expect(parse({ enabled: "true" })?.enabled).toBe(true);
		expect(parse({ enabled: "false" })?.enabled).toBe(false);
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

		// And nothing else, unlike the `z.coerce.number()` of the sections
		// around it: `Number()` reads `null` and `[]` as `0`, `true` as `1` and
		// `"1e3"` as `1000`, which would NORMALISE a malformed duration before
		// the strict reader downstream — which refuses exactly these — saw it.
		// `tombstoneRetention: null` would disable tombstones silently;
		// `refreshBuffer: null` would hand out tokens with milliseconds left.
		for (const value of ["thirty", "", "1e3", "0x10", -1, 0, 1.5, null, true, false, [], [45]]) {
			expect(() => parse({ maxExpiresIn: value }), JSON.stringify(value)).toThrow();
		}
		for (const value of [null, true, [], "1e3"]) {
			expect(() => parse({ tombstoneRetention: value }), JSON.stringify(value)).toThrow();
		}
	});

	it("holds the tombstone retention to a year, the ceiling of every duration here", () => {
		// Past the Date range it is a deadline no store can keep; a year is the
		// typo guard every duration an operator writes has.
		expect(parse({ tombstoneRetention: 31_536_000 })?.tombstoneRetention).toBe(31_536_000);
		for (const value of [31_536_001, 1e18, "31536001"]) {
			expect(() => parse({ tombstoneRetention: value }), JSON.stringify(value)).toThrow();
		}
	});

	it("is absent when nothing declares it, and an empty block is valid", () => {
		expect(section.parse({} as never).federationGrants).toBeUndefined();
		expect(parse({})).toStrictEqual({});
		// An operator who removed every connection has an empty map, not a
		// missing key: removing the last one must remain an operable change.
		expect(parse({ connections: {} })?.connections).toStrictEqual({});
	});

	it("keeps the vocabulary of the keys whose values are a closed set", () => {
		expect(parse({ encryptionMode: "allow-plaintext" })?.encryptionMode).toBe("allow-plaintext");
		expect(() => parse({ encryptionMode: "off" })).toThrow();
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
});
