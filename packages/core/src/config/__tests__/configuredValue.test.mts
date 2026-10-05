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
 * `configuredNumber` reads a configured value where its owning schema did not
 * run, as core's strict reader does: a number as it is, a string of decimal
 * digits as its number, anything else `undefined`. A hand-built configuration
 * reaches the same answer the schema would give, never a number the operator
 * did not write.
 */

import { describe, expect, it } from "vitest";
import { configuredNumber } from "#/config/configuredValue.mjs";
import { readConfiguredRateLimitSpec } from "#/ratelimit/usableSpec.mjs";

describe("configuredNumber", () => {
	it.each([[60], [0], [-1], [1.5], [Number.NaN]])(
		"hands a number through as it is: %j",
		(value) => {
			expect(configuredNumber(value)).toBe(value);
		},
	);

	it.each([
		["60", 60],
		[" 60 ", 60],
		["0", 0],
	])("reads the decimal digits %j as %j", (value, read) => {
		expect(configuredNumber(value)).toBe(read);
	});

	it.each([
		["0x10"],
		["1e3"],
		["5.0"],
		["+5"],
		["-5"],
		[""],
		["  "],
		["Infinity"],
		["NaN"],
		["9".repeat(400)],
		[true],
		[null],
		[undefined],
		[[60]],
		[{ value: 60 }],
	])("reads %j as no number", (value) => {
		expect(configuredNumber(value)).toBeUndefined();
	});
});

describe("readConfiguredRateLimitSpec reads each field as configuredNumber does", () => {
	it("reads decimal digits", () => {
		expect(readConfiguredRateLimitSpec({ limit: " 20 ", windowSeconds: "60" })).toEqual({
			limit: 20,
			windowSeconds: 60,
		});
	});

	it.each([["0x10"], ["1e3"], ["5.0"], ["+5"]])("has no budget for a limit of %j", (limit) => {
		expect(readConfiguredRateLimitSpec({ limit, windowSeconds: 60 })).toBeUndefined();
	});

	it.each([["0x10"], ["1e3"], ["5.0"], ["+5"]])(
		"has no budget for a window of %j",
		(windowSeconds) => {
			expect(readConfiguredRateLimitSpec({ limit: 20, windowSeconds })).toBeUndefined();
		},
	);
});
