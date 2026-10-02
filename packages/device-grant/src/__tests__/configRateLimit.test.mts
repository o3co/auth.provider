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
 * `device-grant.rateLimit`: the budget RFC 8628 §5.1 sizes the
 * user code against, as a config key that reaches the limiter (otherwise the
 * `device_verification:` prefix falls through to the adapter's 60/60s
 * default). Pins both ends: the schema boundary (defaults and bounds), and the
 * documented key in `reference.conf` resolving, through the real HOCON parser,
 * the budget the module contributes and the real limiter module, to a budget
 * of five.
 */

import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	memoryRateLimiterModule,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { deviceGrantConfigSchema, deviceGrantModule } from "#/module.mjs";
import { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX } from "#/verificationBudget.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

describe("device-grant.rateLimit — schema boundary", () => {
	it("defaults to RFC 8628 §5.1's five attempts per five minutes", () => {
		// §5.1's worked example: ~34.5 bits is sufficient only where "the
		// rate-limiting interval and validity period would need to only
		// allow 5 attempts". Five minutes is half the default code lifetime.
		const parsed = deviceGrantConfigSchema.parse({ enabled: false });
		expect(parsed.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("applies the same default when the whole section is omitted", () => {
		const parsed = deviceGrantConfigSchema.parse(undefined);
		expect(parsed.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("accepts an operator's own budget", () => {
		const parsed = deviceGrantConfigSchema.parse({ rateLimit: { limit: 3, windowSeconds: 600 } });
		expect(parsed.rateLimit).toEqual({ limit: 3, windowSeconds: 600 });
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a negative limit", { limit: -5, windowSeconds: 300 }],
		["a fractional limit", { limit: 2.5, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a window longer than a year", { limit: 5, windowSeconds: 31_536_001 }],
		["a window past the Date range", { limit: 5, windowSeconds: 1e13 }],
		["a missing field", { limit: 5 }],
	])("refuses %s at the config boundary", (_label, rateLimit) => {
		// A zero here is not "no limit" — it is what an empty environment
		// variable coerces to, and a zero-attempt budget locks every user out
		// while a zero window is not a window. Both fail boot, loudly.
		const result = deviceGrantConfigSchema.safeParse({ rateLimit });
		expect(result.success).toBe(false);
	});
});

describe("device-grant.rateLimit — the documented key resolves", () => {
	/**
	 * Six attempts under the verification prefix, on the memory limiter module
	 * reading the budget the device-grant module contributes from `section`: the
	 * advertised limit and which were allowed.
	 */
	const spendSix = async (section: { readonly rateLimit?: unknown }) => {
		const contribute = deviceGrantModule({
			config: { "device-grant": { enabled: true } } as unknown as AppConfig,
		}).contributes?.rateLimitBudgets?.[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX] as (
			deps: unknown,
		) => RateLimitSpec | null;
		const budget = contribute({ section });
		const budgets = new Map(
			budget === null ? [] : [[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX, budget]],
		);
		const provide = memoryRateLimiterModule.provides?.rateLimiter as (deps: unknown) => {
			check(
				key: string,
				ctx: Record<string, unknown>,
			): Promise<{ allowed: boolean; limit?: number }>;
		};
		const limiter = provide({
			section: { limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 }, maxBuckets: 10_000 },
			rateLimitBudgetResolver: {
				get: (prefix: string) => budgets.get(prefix),
				entries: () => budgets.entries(),
			},
		});

		const key = "device_verification:user:user-1";
		const outcomes: boolean[] = [];
		let advertised: number | undefined;
		for (let i = 0; i < 6; i += 1) {
			const decision = await limiter.check(key, { userId: "user-1" });
			advertised ??= decision.limit;
			outcomes.push(decision.allowed);
		}
		return { advertised, outcomes };
	};

	it("reaches the limiter as a budget of five from reference.conf alone", async () => {
		// The shipped HOCON defaults and the schema, the budget the module
		// contributes from them, handed to the memory limiter module through a
		// resolver built here (createApp's is pinned by the composition suite).
		// The sixth attempt under the verification prefix is the one refused.
		const parsed = deviceGrantConfigSchema.parse(
			(parseFile(REFERENCE_CONF).toObject() as { "device-grant": unknown })["device-grant"],
		);
		expect(parsed.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });

		const { advertised, outcomes } = await spendSix(parsed);
		expect(advertised).toBe(5);
		expect(outcomes).toEqual([true, true, true, true, true, false]);
	});

	it("reaches the limiter as a budget of five when the section is omitted entirely", async () => {
		// The route an embedder who hand-assembles config takes: no
		// reference.conf, no `rateLimit` block, just the schema default. It has
		// to travel the same path as the documented key, or the boot refusal
		// reasons from five while the limiter applies sixty.
		const parsed = deviceGrantConfigSchema.parse(undefined);

		const { advertised, outcomes } = await spendSix(parsed);
		expect(advertised).toBe(5);
		expect(outcomes).toEqual([true, true, true, true, true, false]);
	});
});
