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
 * Every number setting of `dpop {}` is read as a whole number in decimal
 * digits: a typo such as `"1e3"` or `"0x10"`, or an exported-but-empty
 * variable, fails boot naming the key instead of being read as some other
 * number.
 */

import { describe, expect, it } from "vitest";
import { dpopConfigSchema } from "#/module.mjs";

/** Each key `dpop {}` reads a number at, with the section that sets it. */
const KEYS: ReadonlyArray<readonly [path: string, set: (value: unknown) => unknown]> = [
	["iatWindowSeconds", (value) => ({ iatWindowSeconds: value })],
	["replayStoreTtlSeconds", (value) => ({ replayStoreTtlSeconds: value })],
	["nonce.ttlSeconds", (value) => ({ nonce: { ttlSeconds: value } })],
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

const issuesAt = (
	result: {
		success: boolean;
		error?: { issues: ReadonlyArray<{ path: PropertyKey[]; message: string }> };
	},
	path: string,
) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === path)
		.map((issue) => issue.message);

describe("dpop {} reads each number setting in decimal digits", () => {
	describe.each(KEYS)("%s", (path, set) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = dpopConfigSchema.safeParse(set(value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([
				"must be a whole number of at least 1, in decimal digits",
			]);
		});

		it.each([[0], ["0"]])("refuses %j, below the minimum", (value) => {
			const result = dpopConfigSchema.safeParse(set(value));
			expect(issuesAt(result, path)).toEqual([
				"must be a whole number of at least 1, in decimal digits",
			]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			const result = dpopConfigSchema.safeParse(set(value));
			expect(result.error?.issues ?? []).toEqual([]);
			const section = result.data as Record<string, unknown> & { nonce: Record<string, unknown> };
			const read = path === "nonce.ttlSeconds" ? section.nonce.ttlSeconds : section[path];
			expect(read).toBe(60);
		});
	});
});
