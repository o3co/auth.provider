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
 * Where a configuration path lands in a Zod schema: what
 * `schemasAtPath` finds through each shape a configuration schema takes, what
 * `outputKinds` can and cannot tell of a schema without running it, and what
 * `pickConfigSchema` reads through a record and refuses.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	outputKinds,
	pickConfigSchema,
	readsEnvironmentString,
	schemasAtPath,
	unreadableLeafPaths,
} from "#/config/schema-path.mjs";

describe("schemasAtPath — the schema that parses the value at a path", () => {
	it("finds a key on either side of an intersection", () => {
		const port = z.number();
		const both = z.object({ host: z.string() }).and(z.object({ port }));
		expect(schemasAtPath(both, ["port"])).toEqual([port]);
		expect(unreadableLeafPaths(both)).toEqual(["port"]);
	});

	it("finds a key through a lazy schema", () => {
		const enabled = z.boolean();
		const lazy = z.lazy(() => z.object({ enabled }));
		expect(schemasAtPath(lazy, ["enabled"])).toEqual([enabled]);
	});

	it("answers any key of a record with the record's value schema", () => {
		const enabled = z.boolean();
		const federations = z.object({ federations: z.record(z.string(), z.object({ enabled })) });
		expect(schemasAtPath(federations, ["federations", "google", "enabled"])).toEqual([enabled]);
		expect(schemasAtPath(federations, ["federations", "google", "missing"])).toEqual([]);
	});
});

describe("unreadableLeafPaths — each path once, sorted", () => {
	it("answers the paths sorted, whatever order the schema declares them in", () => {
		expect(
			unreadableLeafPaths(z.object({ zeta: z.boolean(), alpha: z.number(), mid: z.boolean() })),
		).toEqual(["alpha", "mid", "zeta"]);
	});

	it("names a path two members of a union both declare unreadable once", () => {
		const either = z.union([z.object({ a: z.boolean() }), z.object({ a: z.number() })]);
		expect(unreadableLeafPaths(either)).toEqual(["a"]);
	});
});

describe("outputKinds — what a schema produces, when it can be told without running it", () => {
	it("gathers every member's kind in a union", () => {
		expect(outputKinds(z.union([z.boolean(), z.string()]))).toEqual(new Set(["boolean", "string"]));
	});

	it("cannot tell a union with a member it cannot tell", () => {
		expect(outputKinds(z.union([z.string(), z.string().transform(Number)]))).toBeUndefined();
	});

	it("tells a literal by its values, and an enum as strings", () => {
		expect(outputKinds(z.literal(true))).toEqual(new Set(["boolean"]));
		expect(outputKinds(z.literal(3))).toEqual(new Set(["number"]));
		expect(outputKinds(z.enum(["memory", "redis"]))).toEqual(new Set(["string"]));
	});

	it("cannot tell a transform, a custom schema, any, unknown or a lazy schema", () => {
		for (const schema of [
			z.transform((value: unknown) => value),
			z.custom<string>(() => true),
			z.any(),
			z.unknown(),
			z.lazy(() => z.string()),
		]) {
			expect(outputKinds(schema), schema._zod.def.type).toBeUndefined();
		}
	});

	it("tells a preprocess by what it hands its schema, and a plain schema by its type", () => {
		expect(outputKinds(z.preprocess((value) => value, z.boolean()))).toEqual(new Set(["boolean"]));
		expect(outputKinds(z.number().optional())).toEqual(new Set(["number"]));
	});
});

describe("pickConfigSchema — the schema of the paths read alone", () => {
	const schema = z.object({
		federations: z.record(
			z.string(),
			z.object({ enabled: z.coerce.boolean(), clientId: z.string() }),
		),
	});

	it("reads a path through a record's entry, with the entry's own schema", () => {
		const picked = pickConfigSchema(schema, ["federations.google.enabled"]);
		expect(picked.parse({ federations: { google: { enabled: "true", clientId: 1 } } })).toEqual({
			federations: { google: { enabled: true } },
		});
	});

	it("refuses a path a union offers several schemas for, naming how many", () => {
		const either = z.object({
			a: z.union([z.object({ b: z.string() }), z.object({ b: z.number() })]),
		});
		expect(() => pickConfigSchema(either, ["a.b"])).toThrow(
			new RangeError(
				'cannot read "a.b": the configuration schema declares 2 schemas there — read a shorter path',
			),
		);
	});

	it("reads an absent ancestor of a picked path as the default the schema declares for it", () => {
		const defaulted = z.object({
			section: z.object({ mode: z.enum(["off", "on"]).default("off") }).default({ mode: "off" }),
			other: z.object({ mode: z.enum(["off", "on"]) }).optional(),
		});
		const picked = pickConfigSchema(defaulted, ["section.mode", "other.mode"]);
		expect(picked.parse({})).toEqual({ section: { mode: "off" } });
		expect(picked.parse({ section: { mode: "on" }, other: { mode: "on" } })).toEqual({
			section: { mode: "on" },
			other: { mode: "on" },
		});
	});

	it("refuses a path with an empty key", () => {
		for (const path of ["federations..enabled", ".federations", "federations."]) {
			expect(() => pickConfigSchema(schema, [path]), path).toThrow(
				new RangeError(`cannot read "${path}": not a dot-separated path of non-empty keys`),
			);
		}
	});
});

describe("readsEnvironmentString — every scalar type classified, an unknown one refused", () => {
	it.each([
		["a string", z.string()],
		["an enum", z.enum(["memory", "redis"])],
		["a string literal", z.literal("on")],
		["a template literal", z.templateLiteral(["v", z.number()])],
		["z.coerce.string()", z.coerce.string()],
		["z.coerce.number()", z.coerce.number()],
		["z.coerce.boolean()", z.coerce.boolean()],
		["z.coerce.bigint()", z.coerce.bigint()],
		["z.coerce.date()", z.coerce.date()],
		["any", z.any()],
		["unknown", z.unknown()],
	])("reads the string with %s", (_label, schema) => {
		expect(readsEnvironmentString(schema)).toBe(true);
	});

	it.each([
		["a boolean", z.boolean()],
		["a number", z.number()],
		["a bigint", z.bigint()],
		["a date", z.date()],
		["null", z.null()],
		["undefined", z.undefined()],
		["void", z.void()],
		["never", z.never()],
		["NaN", z.nan()],
		["a symbol", z.symbol()],
		["a custom schema", z.custom<string>((value) => typeof value === "string")],
		["a map", z.map(z.string(), z.string())],
		["a set", z.set(z.string())],
		["a tuple", z.tuple([z.string()])],
		["a numeric literal", z.literal(1)],
	])("does not read the string with %s", (_label, schema) => {
		expect(readsEnvironmentString(schema)).toBe(false);
	});

	it("reports a leaf of a type it does not read, in an object", () => {
		expect(unreadableLeafPaths(z.object({ value: z.date(), name: z.string() }))).toEqual(["value"]);
	});
});
