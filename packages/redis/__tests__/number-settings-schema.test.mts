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
 * Every number setting of the Redis modules' sections is read as a whole
 * number in decimal digits, held to its range: a typo such as `"1e3"` or
 * `"0x10"`, or an exported-but-empty variable, fails boot naming the key
 * instead of being read as some other number.
 */

import { MAX_DURATION_SECONDS } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { redisCodeRepositoryModule } from "#/code-repository.mjs";
import { redisFederationTokenStoreSectionSchema } from "#/federation-tokens.mjs";
import { redisRateLimiterSectionSchema } from "#/ratelimit.mjs";
import { redisRefreshTokenFamilyStoreSectionSchema } from "#/refresh-token-family.mjs";

const codeRepositorySchema = (): z.ZodType => {
	const schema = redisCodeRepositoryModule.section?.schema;
	if (schema === undefined) throw new Error("redisCodeRepositoryModule declares no section");
	return schema as z.ZodType;
};

const AT_LEAST_1 = "must be a whole number of at least 1, in decimal digits";
const WINDOW = `must be a whole number from 1 to ${MAX_DURATION_SECONDS}, in decimal digits`;

/** Each number key: its section and path, the section that sets it, its range's message, and a value inside the range. */
const KEYS: ReadonlyArray<
	readonly [
		name: string,
		schema: () => z.ZodType,
		path: string,
		set: (value: unknown) => unknown,
		message: string,
		inRange: number,
	]
> = [
	[
		"redis-rate-limiter.defaultLimit.limit",
		() => redisRateLimiterSectionSchema,
		"defaultLimit.limit",
		(value) => ({ defaultLimit: { limit: value, windowSeconds: 60 } }),
		AT_LEAST_1,
		5,
	],
	[
		"redis-rate-limiter.defaultLimit.windowSeconds",
		() => redisRateLimiterSectionSchema,
		"defaultLimit.windowSeconds",
		(value) => ({ defaultLimit: { limit: 5, windowSeconds: value } }),
		WINDOW,
		5,
	],
	[
		"redis-rate-limiter.limits.token.limit",
		() => redisRateLimiterSectionSchema,
		"limits.token.limit",
		(value) => ({ limits: { token: { limit: value, windowSeconds: 60 } } }),
		AT_LEAST_1,
		5,
	],
	[
		"redis-rate-limiter.limits.token.windowSeconds",
		() => redisRateLimiterSectionSchema,
		"limits.token.windowSeconds",
		(value) => ({ limits: { token: { limit: 5, windowSeconds: value } } }),
		WINDOW,
		5,
	],
	[
		"redis-refresh-token-family-store.casRetryLimit",
		() => redisRefreshTokenFamilyStoreSectionSchema,
		"casRetryLimit",
		(value) => ({ casRetryLimit: value }),
		"must be a whole number from 1 to 10, in decimal digits",
		5,
	],
	[
		"redis-federation-token-store.ttl",
		() => redisFederationTokenStoreSectionSchema,
		"ttl",
		(value) => ({ ttl: value }),
		AT_LEAST_1,
		5,
	],
	[
		"redis-code-repository.defaultExpiresIn",
		codeRepositorySchema,
		"defaultExpiresIn",
		(value) => ({ defaultExpiresIn: value }),
		AT_LEAST_1,
		5,
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

const issuesAt = (result: ReturnType<z.ZodType["safeParse"]>, path: string) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === path)
		.map((issue) => issue.message);

/** The value the parsed section carries at `path`. */
const readAt = (section: unknown, path: string): unknown =>
	path
		.split(".")
		.reduce<unknown>((node, key) => (node as Record<string, unknown> | undefined)?.[key], section);

describe("the Redis sections read each number setting in decimal digits, held to its range", () => {
	describe.each(KEYS)("%s", (_name, schema, path, set, message, inRange) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = schema().safeParse(set(value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([message]);
		});

		it.each([[0], ["0"]])("refuses %j, below the minimum", (value) => {
			expect(issuesAt(schema().safeParse(set(value)), path)).toEqual([message]);
		});

		it.each([[inRange], [`${inRange}`], [` ${inRange} `]])("reads %j", (value) => {
			const result = schema().safeParse(set(value));
			expect(result.error?.issues ?? []).toEqual([]);
			expect(readAt(result.data, path)).toBe(inRange);
		});
	});

	it.each([
		[
			"defaultLimit.windowSeconds",
			{ defaultLimit: { limit: 5, windowSeconds: MAX_DURATION_SECONDS + 1 } },
		],
		[
			"limits.token.windowSeconds",
			{ limits: { token: { limit: 5, windowSeconds: MAX_DURATION_SECONDS + 1 } } },
		],
	] as const)("refuses redis-rate-limiter.%s past one year", (path, section) => {
		expect(issuesAt(redisRateLimiterSectionSchema.safeParse(section), path)).toEqual([WINDOW]);
	});

	it("refuses redis-refresh-token-family-store.casRetryLimit above 10", () => {
		expect(
			issuesAt(
				redisRefreshTokenFamilyStoreSectionSchema.safeParse({ casRetryLimit: 11 }),
				"casRetryLimit",
			),
		).toEqual(["must be a whole number from 1 to 10, in decimal digits"]);
	});
});
