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
 * `wholeNumberFromEnv`, core's public strict reader of a whole number an
 * environment variable may carry: a number as written, or a string of decimal
 * digits, whitespace around them allowed. Every other shape reaches the bounds
 * unchanged and is refused there, never read as a number.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { readsEnvironmentString } from "#/config/schema-path.mjs";
import { wholeNumberFromEnv, wholeNumberInRangeFromEnv } from "#/index.mjs";

const reader = () => wholeNumberFromEnv(z.number().int().min(0).max(65_535));

describe("wholeNumberFromEnv", () => {
	it.each([
		[8080, 8080],
		[0, 0],
		["8080", 8080],
		["0", 0],
		[" 8080 ", 8080],
	])("reads %j as %j", (written, read) => {
		expect(reader().parse(written)).toBe(read);
	});

	it.each([
		["the empty string an exported-but-empty variable carries", ""],
		["blank", "  "],
		["hexadecimal", "0x50"],
		["an exponent", "8e3"],
		["the string Infinity", "Infinity"],
		["the string NaN", "NaN"],
		["Infinity", Number.POSITIVE_INFINITY],
		["NaN", Number.NaN],
		["a sign", "+80"],
		["a negative", "-1"],
		["a fraction", "80.5"],
		["null", null],
		["true", true],
		["an empty list", []],
	])("refuses %s", (_what, written) => {
		expect(reader().safeParse(written).success).toBe(false);
	});

	it("holds a number to the bounds it was given", () => {
		expect(reader().safeParse(65_536).success).toBe(false);
		expect(reader().safeParse("65536").success).toBe(false);
		expect(reader().safeParse(1.5).success).toBe(false);
	});

	it("is one of the readers the environment-string guard trusts", () => {
		expect(readsEnvironmentString(reader())).toBe(true);
		expect(readsEnvironmentString(reader().optional())).toBe(true);
	});
});

/** Every form an operator might write that is not a whole number in decimal digits. */
const NOT_DECIMAL_DIGITS: ReadonlyArray<readonly [string, unknown]> = [
	["the empty string an exported-but-empty variable carries", ""],
	["blank", "  "],
	["hexadecimal", "0x10"],
	["an exponent", "1e3"],
	["a decimal point", "5.0"],
	["the string Infinity", "Infinity"],
	["the string NaN", "NaN"],
	["Infinity", Number.POSITIVE_INFINITY],
	["NaN", Number.NaN],
	["a sign", "+5"],
	["a negative", "-5"],
	["a fraction", "5.5"],
	["a fractional number", 5.5],
	["null", null],
	["true", true],
];

describe("wholeNumberInRangeFromEnv", () => {
	it.each([
		[5, 5],
		["5", 5],
		[" 60 ", 60],
		[1, 1],
		["100", 100],
	])("reads %j as %j", (written, read) => {
		expect(wholeNumberInRangeFromEnv(1, 100).parse(written)).toBe(read);
	});

	it.each(NOT_DECIMAL_DIGITS)("refuses %s, naming the range and the form", (_what, written) => {
		const result = wholeNumberInRangeFromEnv(1, 100).safeParse(written);
		expect(result.success).toBe(false);
		expect(result.error?.issues.map((issue) => issue.message)).toEqual([
			"must be a whole number from 1 to 100, in decimal digits",
		]);
	});

	it("refuses a whole number outside the range, with the same message", () => {
		for (const written of [0, "0", 101, "101"]) {
			const result = wholeNumberInRangeFromEnv(1, 100).safeParse(written);
			expect(
				result.error?.issues.map((issue) => issue.message),
				String(written),
			).toEqual(["must be a whole number from 1 to 100, in decimal digits"]);
		}
	});

	it("without a maximum, holds a number to the minimum alone", () => {
		expect(wholeNumberInRangeFromEnv(1).parse("9007199254740991")).toBe(Number.MAX_SAFE_INTEGER);
		const result = wholeNumberInRangeFromEnv(1).safeParse("0");
		expect(result.error?.issues.map((issue) => issue.message)).toEqual([
			"must be a whole number of at least 1, in decimal digits",
		]);
	});

	it("is one of the readers the environment-string guard trusts", () => {
		expect(readsEnvironmentString(wholeNumberInRangeFromEnv(1))).toBe(true);
		expect(readsEnvironmentString(wholeNumberInRangeFromEnv(1, 100).optional())).toBe(true);
	});
});
