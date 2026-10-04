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
 * Every number setting of `device-grant {}` is read as a whole number in
 * decimal digits, held to its range: a typo such as `"1e3"` or `"0x10"`, or
 * an exported-but-empty variable, fails boot naming the key instead of being
 * read as some other number.
 */

import { MAX_DURATION_SECONDS } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { deviceGrantConfigSchema } from "#/module.mjs";
import { shippedDeviceGrantSection } from "./shippedSection.mjs";

/** Each key `device-grant {}` reads a number at: the keys that set it over the shipped section, its range's message, and a value inside the range. */
const KEYS: ReadonlyArray<
	readonly [path: string, set: (value: unknown) => unknown, message: string, inRange: number]
> = [
	[
		"rateLimit.limit",
		(value) => ({ rateLimit: { limit: value, windowSeconds: 300 } }),
		"must be a whole number of at least 1, in decimal digits",
		60,
	],
	[
		"rateLimit.windowSeconds",
		(value) => ({ rateLimit: { limit: 5, windowSeconds: value } }),
		`must be a whole number from 1 to ${MAX_DURATION_SECONDS}, in decimal digits`,
		60,
	],
	[
		"codeLifetimeSeconds",
		(value) => ({ codeLifetimeSeconds: value }),
		"must be a whole number from 30 to 3600, in decimal digits",
		60,
	],
	[
		"pollingIntervalSeconds",
		(value) => ({ pollingIntervalSeconds: value }),
		"must be a whole number from 1 to 60, in decimal digits",
		60,
	],
];

/** What an operator might write that is not a whole number in decimal digits. */
const REFUSED: ReadonlyArray<unknown> = [
	"0x10",
	"1e3",
	"5.0",
	"+5",
	true,
	"",
	"  ",
	"Infinity",
	"NaN",
	Number.POSITIVE_INFINITY,
	Number.NaN,
];

/** The shipped section with `overrides` laid over it, parsed. */
const parse = (overrides: unknown) =>
	deviceGrantConfigSchema.safeParse(
		shippedDeviceGrantSection(overrides as Readonly<Record<string, unknown>>),
	);

const issuesAt = (result: ReturnType<typeof deviceGrantConfigSchema.safeParse>, path: string) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === path)
		.map((issue) => issue.message);

/** The value the parsed section carries at `path`. */
const readAt = (section: unknown, path: string): unknown =>
	path
		.split(".")
		.reduce<unknown>((node, key) => (node as Record<string, unknown> | undefined)?.[key], section);

describe("device-grant {} reads each number setting in decimal digits, held to its range", () => {
	describe.each(KEYS)("%s", (path, set, message, inRange) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = parse(set(value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([message]);
		});

		it.each([[0], ["0"]])("refuses %j, below the minimum", (value) => {
			expect(issuesAt(parse(set(value)), path)).toEqual([message]);
		});

		it.each([[inRange], [`${inRange}`], [` ${inRange} `]])("reads %j", (value) => {
			const result = parse(set(value));
			expect(result.error?.issues ?? []).toEqual([]);
			expect(readAt(result.data, path)).toBe(inRange);
		});
	});

	it.each([
		["rateLimit.windowSeconds", MAX_DURATION_SECONDS + 1],
		["codeLifetimeSeconds", 3601],
		["pollingIntervalSeconds", 61],
	] as const)("refuses %s = %d, above the maximum", (path, value) => {
		const [, set, message] = KEYS.find(([key]) => key === path) ?? [];
		expect(set === undefined ? [] : issuesAt(parse(set(value)), path)).toEqual([message]);
	});
});
