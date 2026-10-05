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
 * Every number setting of `oauth.clientIdMetadataDocuments` is read as a
 * whole number in decimal digits, held to its range: a typo such as `"1e3"`
 * or `"0x10"`, or an exported-but-empty variable, fails boot naming the key
 * instead of being read as some other number.
 */

import { describe, expect, it } from "vitest";
import { oauthSectionSchema } from "#/module.mjs";

const AT_LEAST_1 = "must be a whole number of at least 1, in decimal digits";
const AT_LEAST_0 = "must be a whole number of at least 0, in decimal digits";

/** Each key `oauth.clientIdMetadataDocuments` reads a number at, with its range's message. */
const KEYS: ReadonlyArray<readonly [key: string, message: string]> = [
	["maxBytes", AT_LEAST_1],
	["timeoutMs", AT_LEAST_1],
	["cacheMaxAgeMs", AT_LEAST_0],
	["maxCacheEntries", AT_LEAST_1],
	["staleIfErrorMs", AT_LEAST_0],
	["negativeCacheMs", AT_LEAST_0],
	["maxConcurrentFetches", AT_LEAST_1],
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

/** The keys of `oauth {}` its schema requires. */
const REQUIRED = {
	jwt: { issuer: "https://auth.test" },
	accessToken: { expiresIn: 3600 },
	refreshToken: { expiresIn: 86400 },
	oidcMode: "oidc-required",
};

const parse = (key: string, value: unknown) =>
	oauthSectionSchema.safeParse({
		...REQUIRED,
		clientIdMetadataDocuments: { enabled: false, [key]: value },
	});

const issuesAt = (result: ReturnType<typeof parse>, key: string) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === `clientIdMetadataDocuments.${key}`)
		.map((issue) => issue.message);

/** The value the parsed section carries at `key`. */
const readAt = (result: ReturnType<typeof parse>, key: string) =>
	(result.data?.clientIdMetadataDocuments as Record<string, unknown> | undefined)?.[key];

describe("oauth.clientIdMetadataDocuments reads each number setting in decimal digits", () => {
	describe.each(KEYS)("%s", (key, message) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = parse(key, value);
			expect(result.success).toBe(false);
			expect(issuesAt(result, key)).toEqual([message]);
		});

		it("refuses a value below the minimum", () => {
			const below = message === AT_LEAST_0 ? -1 : 0;
			expect(issuesAt(parse(key, below), key)).toEqual([message]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			const result = parse(key, value);
			expect(result.error?.issues ?? []).toEqual([]);
			expect(readAt(result, key)).toBe(60);
		});
	});

	it.each(["cacheMaxAgeMs", "staleIfErrorMs", "negativeCacheMs"])("reads %s = 0", (key) => {
		const result = parse(key, "0");
		expect(readAt(result, key)).toBe(0);
	});
});
