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
 * Every number setting core's own schemas declare is read as a whole number
 * in decimal digits: a typo such as `"1e9"` or `"0x10"`, or an
 * exported-but-empty variable, fails boot naming the key instead of being
 * read as some other number.
 */

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { memoryRateLimiterSectionSchema } from "#/ratelimit/module.mjs";
import { createRepositoryFactories } from "#/repositories/RepositoryFactory.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

type AppConfigInput = ReturnType<typeof makeValidAppConfig>;

/** Each key core's application schema reads a number at, with the config that sets it. */
const APP_CONFIG_KEYS: ReadonlyArray<
	readonly [path: string, set: (base: AppConfigInput, value: unknown) => unknown]
> = [
	[
		"oauth.accessToken.defaultExpiresIn",
		(base, value) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { defaultExpiresIn: value } },
		}),
	],
	[
		"oauth.accessToken.maxExpiresIn",
		(base, value) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { expiresIn: 60, maxExpiresIn: value } },
		}),
	],
	[
		"oauth.accessToken.expiresIn",
		(base, value) => ({ ...base, oauth: { ...base.oauth, accessToken: { expiresIn: value } } }),
	],
	[
		"oauth.refreshToken.expiresIn",
		(base, value) => ({
			...base,
			oauth: { ...base.oauth, refreshToken: { ...base.oauth.refreshToken, expiresIn: value } },
		}),
	],
	[
		"oauth.nonce.maxLength",
		(base, value) => ({ ...base, oauth: { ...base.oauth, nonce: { maxLength: value } } }),
	],
	["webauthn.challengeTtlMs", (base, value) => ({ ...base, webauthn: { challengeTtlMs: value } })],
	[
		"webauthn.rateLimit.authenticationOptions.limit",
		(base, value) => ({
			...base,
			webauthn: { rateLimit: { authenticationOptions: { limit: value, windowSeconds: 60 } } },
		}),
	],
	[
		"webauthn.rateLimit.authenticationOptions.windowSeconds",
		(base, value) => ({
			...base,
			webauthn: { rateLimit: { authenticationOptions: { limit: 5, windowSeconds: value } } },
		}),
	],
];

/** Each key the memory rate limiter's section reads a number at, with the section that sets it. */
const RATE_LIMITER_KEYS: ReadonlyArray<readonly [path: string, set: (value: unknown) => unknown]> =
	[
		["maxBuckets", (value) => ({ maxBuckets: value })],
		["defaultLimit.limit", (value) => ({ defaultLimit: { limit: value, windowSeconds: 60 } })],
		[
			"defaultLimit.windowSeconds",
			(value) => ({ defaultLimit: { limit: 5, windowSeconds: value } }),
		],
		["limits.token.limit", (value) => ({ limits: { token: { limit: value, windowSeconds: 60 } } })],
		[
			"limits.token.windowSeconds",
			(value) => ({ limits: { token: { limit: 5, windowSeconds: value } } }),
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

describe("core's application schema reads each number setting in decimal digits", () => {
	describe.each(APP_CONFIG_KEYS)("%s", (path, set) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = AppConfigSchema.safeParse(set(makeValidAppConfig(), value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([
				expect.stringMatching(/^must be a whole number .*, in decimal digits$/),
			]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			const result = AppConfigSchema.safeParse(set(makeValidAppConfig(), value));
			expect(result.error?.issues ?? []).toEqual([]);
		});
	});
});

describe("the memory rate limiter's section reads each number setting in decimal digits", () => {
	describe.each(RATE_LIMITER_KEYS)("%s", (path, set) => {
		it.each(REFUSED.map((value) => [value]))("refuses %j, naming the key", (value) => {
			const result = memoryRateLimiterSectionSchema.safeParse(set(value));
			expect(result.success).toBe(false);
			expect(issuesAt(result, path)).toEqual([
				expect.stringMatching(/^must be a whole number .*, in decimal digits$/),
			]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
			expect(memoryRateLimiterSectionSchema.safeParse(set(value)).error?.issues ?? []).toEqual([]);
		});
	});
});

describe("the memory code repository reads defaultExpiresIn in decimal digits", () => {
	it.each(["0x3c", "6e1", "60.0", "+60", true, "Infinity"])(
		"refuses %j",
		async (defaultExpiresIn) => {
			const { codeFactory } = createRepositoryFactories();
			await expect(codeFactory.create({ type: "memory", defaultExpiresIn })).rejects.toThrow(
				'"defaultExpiresIn" must be a positive whole number of seconds, in decimal digits',
			);
		},
	);

	it("reads a string of decimal digits", async () => {
		const { codeFactory } = createRepositoryFactories();
		await expect(
			codeFactory.create({ type: "memory", defaultExpiresIn: " 60 " }),
		).resolves.toBeDefined();
	});
});
