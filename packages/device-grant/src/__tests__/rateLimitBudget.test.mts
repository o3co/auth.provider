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
 * The device grant's `device_verification` budget: the verification
 * endpoint's `device_verification:user:<subject>` limit, which RFC 8628 §5.1
 * sizes the user code's entropy against. The module contributes
 * `device-grant.rateLimit` as a `rateLimitBudgets` entry for
 * every limiter to read; without it a shared limiter would serve the
 * endpoint its `defaultLimit` of 60 per 60 s, twelve times the five attempts
 * the boot refusal reasons from.
 */

import {
	type AppConfig,
	isUsableRateLimitSpec,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import {
	DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
	isDeviceVerificationRateLimitSpec,
} from "#/verificationBudget.mjs";

const switchedOn = (enabled: boolean) => ({ "device-grant": { enabled } }) as unknown as AppConfig;

/** What the module, built with the grant `enabled` or not, contributes for `device_verification`. */
const verificationBudget = async (
	section: unknown,
	enabled = true,
): Promise<RateLimitSpec | null | undefined> =>
	deviceGrantModule({ config: switchedOn(enabled) }).contributes?.rateLimitBudgets?.[
		DEVICE_VERIFICATION_RATE_LIMIT_PREFIX
	]?.({ section } as never);

describe("the device grant's device_verification budget", () => {
	it("is keyed by the prefix the verification endpoint limits under", () => {
		expect(DEVICE_VERIFICATION_RATE_LIMIT_PREFIX).toBe("device_verification");
	});

	it("is device-grant.rateLimit while the grant is on", async () => {
		expect(await verificationBudget({ rateLimit: { limit: 5, windowSeconds: 300 } })).toEqual({
			limit: 5,
			windowSeconds: 300,
		});
	});

	it("is not contributed while the grant is off: the module registers nothing", async () => {
		expect(
			await verificationBudget({ rateLimit: { limit: 5, windowSeconds: 300 } }, false),
		).toBeUndefined();
	});

	it("is switched off when the section gives no budget", async () => {
		expect(await verificationBudget({})).toBeNull();
	});

	it("reads the key as the schema does: a numeric string is its number", async () => {
		expect(await verificationBudget({ rateLimit: { limit: "5", windowSeconds: "300" } })).toEqual({
			limit: 5,
			windowSeconds: 300,
		});
	});

	it("reads a string only as decimal digits", async () => {
		expect(
			await verificationBudget({ rateLimit: { limit: " 5 ", windowSeconds: " 300 " } }),
		).toEqual({ limit: 5, windowSeconds: 300 });
		for (const [limit, windowSeconds] of [
			["0x10", 300],
			["1e1", 300],
			["5.0", 300],
			["+5", 300],
			[5, "0x12c"],
			[5, "3e2"],
			[5, "300.0"],
			[5, "+300"],
		]) {
			await expect(
				verificationBudget({ rateLimit: { limit, windowSeconds } }),
				`limit=${JSON.stringify(limit)} windowSeconds=${JSON.stringify(windowSeconds)}`,
			).rejects.toThrow(/^device-grant\.rateLimit must be/);
		}
	});

	it("refuses a budget that is given but unusable, naming the key", async () => {
		for (const [limit, windowSeconds] of [
			[0, 300],
			[5, 0],
			[-1, 300],
			[2.5, 300],
			[5, 2.5],
			["five", 300],
			[5, ""],
			["  ", 300],
			[true, 300],
			[5, [300]],
			["2.5", 300],
			[5, 1e13],
		]) {
			await expect(
				verificationBudget({ rateLimit: { limit, windowSeconds } }),
				`limit=${JSON.stringify(limit)} windowSeconds=${JSON.stringify(windowSeconds)}`,
			).rejects.toThrow(/^device-grant\.rateLimit must be/);
		}
		await expect(
			verificationBudget({ rateLimit: { limit: "five", windowSeconds: 300 } }),
		).rejects.toThrow(/\(got limit "five", windowSeconds 300\)$/);
		await expect(verificationBudget({ rateLimit: null })).rejects.toThrow(
			/^device-grant\.rateLimit must be/,
		);
	});
});

describe("isDeviceVerificationRateLimitSpec", () => {
	it("accepts a positive-integer limit and window", () => {
		expect(isDeviceVerificationRateLimitSpec({ limit: 5, windowSeconds: 300 })).toBe(true);
	});

	it("is the one predicate every limiter judges a spec by", () => {
		// The budget this module contributes, its boot refusal and both
		// limiters' refusal at construction answer the same question.
		expect(isDeviceVerificationRateLimitSpec).toBe(isUsableRateLimitSpec);
	});

	it.each([
		["an absent section", undefined],
		["null", null],
		["a non-object", "5/300"],
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a negative limit", { limit: -1, windowSeconds: 300 }],
		["a fractional limit", { limit: 2.5, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 2.5 }],
		["a string limit", { limit: "5", windowSeconds: 300 }],
		["a string window", { limit: 5, windowSeconds: "300" }],
		["a missing window", { limit: 5 }],
		["a missing limit", { windowSeconds: 300 }],
		["a window past the Date range", { limit: 5, windowSeconds: 1e13 }],
	])("refuses %s", (_label, value) => {
		// `0` is what an empty environment variable coerces to, and a budget
		// invented from it is worse than the limiter's own default.
		expect(isDeviceVerificationRateLimitSpec(value)).toBe(false);
	});
});
