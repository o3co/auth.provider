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
 * #728: every configuration leaf core's schema declares reads the string an
 * environment variable arrives as. HOCON substitutes `${?VAR}` as a string,
 * always — in a shipped file or in an operator's own. The HOCON library's Zod
 * bridge used to coerce a bare `z.boolean()` / `z.number()` leaf on the way
 * into the standalone template's pre-parse; boot's one composed parse is
 * plain Zod, so such a leaf would refuse `"false"` where it used to read
 * `false`: a deployment that booted before, refused now.
 *
 * It walks core's transitional base — core's sections and every section it
 * mirrors — through objects, records and lists. The modules' own schemas are
 * held to the same rule where they are all loaded (`tools/composition`,
 * `unreadableModuleLeaves` from the testing entry).
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { TransitionalConfigSchema } from "#/config/composed.mjs";
import { readsEnvironmentString, unreadableLeafPaths } from "#/config/schema-path.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

describe("every leaf core's schema declares reads the string an environment variable arrives as (#728)", () => {
	it("walks the whole base (the guard is not vacuous)", () => {
		const unreadable = unreadableLeafPaths(
			z.object({
				a: z.object({ b: z.boolean(), c: z.coerce.number() }),
				d: z.record(z.string(), z.number()),
			}),
		);
		expect(unreadable).toEqual(["a.b", "d.*"]);
	});

	it("finds no bare boolean, and no number that does not coerce", () => {
		expect(unreadableLeafPaths(TransitionalConfigSchema)).toEqual([]);
	});

	it("tells a leaf that reads a string from one that does not", () => {
		expect(readsEnvironmentString(z.boolean())).toBe(false);
		expect(readsEnvironmentString(z.number().int().optional())).toBe(false);
		expect(readsEnvironmentString(z.coerce.number())).toBe(true);
		expect(readsEnvironmentString(z.preprocess((value) => value, z.boolean()))).toBe(true);
		expect(readsEnvironmentString(z.union([z.boolean(), z.string()]))).toBe(true);
		expect(readsEnvironmentString(z.enum(["a", "b"]))).toBe(true);
	});
});

describe("the two leaves the bridge used to coerce, read from the strings an operator's variables carry", () => {
	const base = makeValidCoreConfig();

	it("oauth.jwt.jwksCacheMaxAge", () => {
		const parsed = TransitionalConfigSchema.parse({
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, jwksCacheMaxAge: "600" } },
		});
		expect(parsed.oauth.jwt.jwksCacheMaxAge).toBe(600);
	});

	it("redisFederationTokenStore.scanFallback", () => {
		for (const [written, read] of [
			["false", false],
			["true", true],
		] as const) {
			const parsed = TransitionalConfigSchema.parse({
				...base,
				redisFederationTokenStore: { scanFallback: written },
			});
			expect(parsed.redisFederationTokenStore?.scanFallback, written).toBe(read);
		}
	});
});
