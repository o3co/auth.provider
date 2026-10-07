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
 * Every number setting of `mtls {}` is read as a whole number in decimal
 * digits, held to its range: a typo such as `"1e3"` or `"0x10"`, or an empty
 * value, fails boot naming the key instead of being read as some other number.
 */

import { describe, expect, it } from "vitest";
import { mtlsConfigSchema } from "#/module.mjs";
import { shippedMtlsSection } from "./shippedSection.mjs";

/** The shipped section with `settings` laid over its `fullPki` block. */
const fullPki = (settings: Record<string, unknown>) => shippedMtlsSection({ fullPki: settings });
const revocation = (settings: Record<string, unknown>) =>
	fullPki({ revocation: { mode: "crl", onUnavailable: "reject", ...settings } });

/** Each key `mtls {}` reads a number at: the section that sets it, its range's message, and a value inside the range. */
const KEYS: ReadonlyArray<
	readonly [path: string, set: (value: unknown) => unknown, message: string, inRange: number]
> = [
	[
		"fullPki.maxChainDepth",
		(value) => fullPki({ maxChainDepth: value }),
		"must be a whole number from 2 to 16, in decimal digits",
		6,
	],
	[
		"fullPki.minRsaKeyBits",
		(value) => fullPki({ minRsaKeyBits: value }),
		"must be a whole number of at least 1024, in decimal digits",
		2048,
	],
	[
		"fullPki.revocation.fetchTimeoutMs",
		(value) => revocation({ fetchTimeoutMs: value }),
		"must be a whole number of at least 1, in decimal digits",
		60,
	],
	[
		"fullPki.revocation.cacheTtlSeconds",
		(value) => revocation({ cacheTtlSeconds: value }),
		"must be a whole number of at least 0, in decimal digits",
		60,
	],
	[
		"fullPki.revocation.maxResponseBytes",
		(value) => revocation({ maxResponseBytes: value }),
		"must be a whole number of at least 1, in decimal digits",
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

const issuesAt = (result: ReturnType<typeof mtlsConfigSchema.safeParse>, path: string) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === path)
		.map((issue) => issue.message);

/** The value the parsed section carries at `path`. */
const readAt = (section: unknown, path: string): unknown =>
	path
		.split(".")
		.reduce<unknown>((node, key) => (node as Record<string, unknown> | undefined)?.[key], section);

describe("mtls {} reads each number setting in decimal digits, held to its range", () => {
	describe.each(KEYS)("%s", (path, set, message, inRange) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = mtlsConfigSchema.safeParse(set(value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([message]);
		});

		it("refuses a value below the minimum", () => {
			const below = path === "fullPki.revocation.cacheTtlSeconds" ? -1 : 0;
			expect(issuesAt(mtlsConfigSchema.safeParse(set(below)), path)).toEqual([message]);
		});

		it.each([[inRange], [`${inRange}`], [` ${inRange} `]])("reads %j", (value) => {
			const result = mtlsConfigSchema.safeParse(set(value));
			expect(result.error?.issues ?? []).toEqual([]);
			expect(readAt(result.data, path)).toBe(inRange);
		});
	});

	it("reads fullPki.revocation.cacheTtlSeconds = 0", () => {
		const result = mtlsConfigSchema.safeParse(revocation({ cacheTtlSeconds: "0" }));
		expect(readAt(result.data, "fullPki.revocation.cacheTtlSeconds")).toBe(0);
	});

	it("refuses fullPki.maxChainDepth above 16", () => {
		expect(
			issuesAt(mtlsConfigSchema.safeParse(fullPki({ maxChainDepth: 17 })), "fullPki.maxChainDepth"),
		).toEqual(["must be a whole number from 2 to 16, in decimal digits"]);
	});
});
