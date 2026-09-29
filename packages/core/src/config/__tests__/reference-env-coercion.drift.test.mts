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
 * Every configuration leaf core's schema declares reads the string an
 * environment variable arrives as. HOCON substitutes `${?VAR}` as a string,
 * always, and boot's one composed parse is plain Zod: a bare `z.boolean()` /
 * `z.number()` leaf would refuse `"false"`.
 *
 * The walk covers core's transitional base (core's sections and every section
 * it mirrors) through objects, records and lists. The modules' own schemas are
 * held to the same rule where they are all loaded (`tools/composition`,
 * `unreadableModuleLeaves` from the testing entry).
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { coerceBooleanFromEnv } from "#/config/application.schema.mjs";
import { TransitionalConfigSchema } from "#/config/composed.mjs";
import {
	readsEnvironmentString,
	schemasAtPath,
	unreadableLeafPaths,
} from "#/config/schema-path.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

describe("every leaf core's schema declares reads the string an environment variable arrives as", () => {
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
		expect(readsEnvironmentString(z.union([z.boolean(), z.string()]))).toBe(true);
		expect(readsEnvironmentString(z.enum(["a", "b"]))).toBe(true);
	});

	it("trusts a preprocess only as far as the schema it hands on, unless it is one of core's environment coercers", () => {
		// A preprocess's function sees the string first, but whether it does
		// anything with it is not something the guard can see: the identity
		// preprocess over a boolean still refuses `"false"`.
		const identity = z.preprocess((value) => value, z.boolean());
		expect(identity.safeParse("false").success).toBe(false);
		expect(readsEnvironmentString(identity)).toBe(false);
		// Judged by what it hands on: a list of strings reads one.
		expect(readsEnvironmentString(z.preprocess((value) => value, z.array(z.string())))).toBe(true);
		// Core's coercers are known to read it.
		expect(readsEnvironmentString(coerceBooleanFromEnv)).toBe(true);
		expect(readsEnvironmentString(coerceBooleanFromEnv.optional())).toBe(true);
		const durations = schemasAtPath(TransitionalConfigSchema, ["oauth", "jwt", "jwksCacheMaxAge"]);
		expect(durations).toHaveLength(1);
		expect(durations.every(readsEnvironmentString)).toBe(true);
		expect(
			schemasAtPath(TransitionalConfigSchema, ["federationGrants", "tombstoneRetention"]).every(
				readsEnvironmentString,
			),
		).toBe(true);
	});
});

describe("oauth.jwt.jwksCacheMaxAge and redisFederationTokenStore.scanFallback, read from the strings an operator's variables carry", () => {
	const base = makeValidCoreConfig();

	const withMaxAge = (jwksCacheMaxAge: unknown) =>
		TransitionalConfigSchema.safeParse({
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, jwksCacheMaxAge } },
		});

	it("oauth.jwt.jwksCacheMaxAge, from the plain decimal string a variable carries", () => {
		for (const [written, read] of [
			["600", 600],
			[" 600 ", 600],
			["0", 0],
			[300, 300],
		] as const) {
			const parsed = withMaxAge(written);
			expect(parsed.success, JSON.stringify(written)).toBe(true);
			if (parsed.success)
				expect(parsed.data.oauth.jwt.jwksCacheMaxAge, JSON.stringify(written)).toBe(read);
		}
	});

	it("oauth.jwt.jwksCacheMaxAge refuses what is not a duration, rather than reading it as 0 or 1", () => {
		// `Number()` reads `""`, `null` and `[]` as 0 and `true` as 1: an
		// exported-but-empty variable would serve `max-age=0`, and every
		// verifier would refetch the JWKS on each check.
		for (const written of ["", null, [], true, "1e3", "-1"]) {
			const parsed = withMaxAge(written);
			expect(parsed.success, JSON.stringify(written)).toBe(false);
			if (!parsed.success) {
				expect(
					parsed.error.issues.map((issue) => issue.path.join(".")),
					JSON.stringify(written),
				).toEqual(["oauth.jwt.jwksCacheMaxAge"]);
			}
		}
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
