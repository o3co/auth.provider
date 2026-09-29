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
 * `unreadableModuleLeaves` (#728): a module's `configSchema` or section leaf
 * that would refuse the string an environment variable carries — a bare
 * `z.boolean()`, a `z.number()` that does not coerce, a non-string literal —
 * is covered only where core's transitional base reads the path first AND
 * hands the module the type the module's leaf takes. A base that reads the
 * string and leaves it a string does not cover a module's number.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { readsEnvironmentString } from "#/config/schema-path.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { unreadableModuleLeaves } from "#/testing/environmentLeaves.mjs";

const reading = (name: string, configSchema: z.ZodObject) => defineModule({ name, configSchema });

describe("unreadableModuleLeaves — what core's base hands a module's leaf", () => {
	it("covers a module's number where the base reads the string as a number", () => {
		// `http.port` is a coerced number in core's base.
		expect(
			unreadableModuleLeaves([
				reading("port-reader", z.object({ http: z.object({ port: z.number() }) })),
			]),
		).toEqual([]);
	});

	it("covers a module's boolean where the base reads the string as a boolean", () => {
		expect(
			unreadableModuleLeaves([
				reading(
					"email-reader",
					z.object({ oauth: z.object({ requireEmailVerified: z.boolean() }) }),
				),
			]),
		).toEqual([]);
	});

	it("does not cover a module's number where the base reads the string and leaves it a string", () => {
		// `logging.level` is an enum of strings: the base reads `"3"` and
		// refuses it, or hands a string on — never the number the module takes.
		expect(
			unreadableModuleLeaves([
				reading("level-reader", z.object({ logging: z.object({ level: z.number() }) })),
			]),
		).toEqual(["level-reader: logging.level"]);
	});

	it("reports a module's preprocess that hands a string on to a boolean untouched", () => {
		expect(
			unreadableModuleLeaves([
				reading(
					"identity-reader",
					z.object({ widget: z.object({ on: z.preprocess((value) => value, z.boolean()) }) }),
				),
			]),
		).toEqual(["identity-reader: widget.on"]);
	});

	it("reports a module's leaf at a path the base does not declare", () => {
		expect(
			unreadableModuleLeaves([
				reading("widget-reader", z.object({ widget: z.object({ on: z.boolean() }) })),
			]),
		).toEqual(["widget-reader: widget.on"]);
	});
});

describe("unreadableModuleLeaves — a module's section, at its path", () => {
	it("reads a section at its `at`, or at the module's name, and a module with neither schema declares none", () => {
		const atPath = defineModule({
			name: "at-path",
			section: { schema: z.object({ on: z.boolean() }), at: "fixture.atPath" },
		});
		const byName = defineModule({
			name: "by-name",
			section: { schema: z.object({ n: z.number() }) },
		});
		expect(unreadableModuleLeaves([atPath, byName, defineModule({ name: "plain" })])).toEqual([
			"at-path: fixture.atPath.on",
			"by-name: by-name.n",
		]);
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
