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
 * `unreadableModuleLeaves`: a module's section leaf, at its name,
 * that would refuse the string an environment variable carries — a bare
 * `z.boolean()`, a `z.number()` that does not coerce, a non-string literal —
 * is reported wherever it is: core's base declares core's own section alone,
 * so it reads no module's leaf first.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { coerceBooleanFromEnv, wholeNumberInRangeFromEnv } from "#/config/application.schema.mjs";
import { readsEnvironmentString } from "#/config/schema-path.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { unreadableModuleLeaves } from "#/testing/environmentLeaves.mjs";

/** A module whose section, at its name, is `schema`. */
const reading = (name: string, schema: z.ZodObject) => defineModule({ name, section: { schema } });

describe("unreadableModuleLeaves — a module's own leaf reads the string, or is reported", () => {
	it.each([
		["a number", { nonce: z.object({ maxLength: z.number() }) }, "oauth: oauth.nonce.maxLength"],
		["a boolean", { requireEmailVerified: z.boolean() }, "oauth: oauth.requireEmailVerified"],
		["a number under a string key", { oidcMode: z.number() }, "oauth: oauth.oidcMode"],
	])("reports %s at a path no core schema declares, oauth {} included", (_, shape, found) => {
		expect(unreadableModuleLeaves([reading("oauth", z.object(shape))])).toEqual([found]);
	});

	it("names a section that is itself a leaf by the module's name", () => {
		expect(
			unreadableModuleLeaves([defineModule({ name: "switch", section: { schema: z.boolean() } })]),
		).toEqual(["switch: switch"]);
	});

	it("reports nothing for a leaf that reads the string itself", () => {
		expect(
			unreadableModuleLeaves([
				reading(
					"oauth",
					z.object({
						requireEmailVerified: coerceBooleanFromEnv.optional(),
						nonce: z.object({ maxLength: wholeNumberInRangeFromEnv(1) }),
					}),
				),
			]),
		).toEqual([]);
	});

	it("reports a module's preprocess that hands a string on to a boolean untouched", () => {
		expect(
			unreadableModuleLeaves([
				reading("widget", z.object({ on: z.preprocess((value) => value, z.boolean()) })),
			]),
		).toEqual(["widget: widget.on"]);
	});

	it("reports a module's leaf at a path the base does not declare", () => {
		expect(unreadableModuleLeaves([reading("widget", z.object({ on: z.boolean() }))])).toEqual([
			"widget: widget.on",
		]);
	});
});

describe("unreadableModuleLeaves — a module's section, at its name", () => {
	it("reads a section at the module's name, not split on its dots, and a module without a section declares none", () => {
		const dotted = defineModule({
			name: "fixture.dotted",
			section: { schema: z.object({ on: z.boolean() }) },
		});
		const byName = defineModule({
			name: "by-name",
			section: { schema: z.object({ n: z.number() }) },
		});
		expect(unreadableModuleLeaves([dotted, byName, defineModule({ name: "plain" })])).toEqual([
			"by-name: by-name.n",
			"fixture.dotted: fixture.dotted.on",
		]);
	});

	it("reads a dotted module name as one key: a section at `oauth.nonce` is not `oauth { nonce }`", () => {
		expect(
			unreadableModuleLeaves([reading("oauth.nonce", z.object({ maxLength: z.number() }))]),
		).toEqual(["oauth.nonce: oauth.nonce.maxLength"]);
	});
});

describe("readsEnvironmentString — a literal reads the string only if it is one", () => {
	it("refuses a boolean or numeric literal, which no string ever equals", () => {
		expect(readsEnvironmentString(z.literal(true))).toBe(false);
		expect(readsEnvironmentString(z.literal(1))).toBe(false);
		expect(readsEnvironmentString(z.literal(true).optional())).toBe(false);
	});

	it("reads a string literal, and a union with one", () => {
		expect(readsEnvironmentString(z.literal("on"))).toBe(true);
		expect(readsEnvironmentString(z.union([z.literal(true), z.literal("on")]))).toBe(true);
	});
});
