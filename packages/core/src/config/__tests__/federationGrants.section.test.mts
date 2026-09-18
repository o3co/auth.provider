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

// The `federationGrants` configuration block (#593, D3, D9, D12, D16).
//
// Declared in core rather than in the route package, for a reason the device
// grant's own comment states: this schema strips keys it does not know, and
// the standalone validates against it before any module's `configSchema`
// runs — so a block only the package knew about would vanish at parse time.
// Here there is a second reason: the Redis grant store reads the same block,
// and it is installed whether or not the routes are.
//
// Presence-and-shape only. The real bounds are enforced where the values are
// used (`assertFederationGrantRetrievalLimits`, the store's constructor), and
// the defaults live in `config/reference.conf` beside every other section's.

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

		// And nothing else. This block used `z.coerce.number()` first, the way
		// the sections around it still do, and Copilot named what that costs
		// HERE: `Number()` reads `null` and `[]` as `0`, `true` as `1` and
		// `"1e3"` as `1000`, so a malformed duration was NORMALISED at the
		// schema and the strict reader downstream — which refuses exactly these
		// — never saw what an operator actually wrote. `tombstoneRetention:
		// null` disabled tombstones silently; `refreshBuffer: null` handed out
		// tokens with milliseconds left on them.
		for (const value of ["thirty", "", "1e3", "0x10", -1, 0, 1.5, null, true, false, [], [45]]) {
			expect(() => parse({ maxExpiresIn: value }), JSON.stringify(value)).toThrow();
		}
		for (const value of [null, true, [], "1e3"]) {
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
		// policy (D15), and a guessed boundary would silently share one.
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
