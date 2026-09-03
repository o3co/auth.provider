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
 * `oauth.deviceAuthorization.rateLimit` — the budget RFC 8628 §5.1 sizes the
 * user code against, as a config key that actually reaches the limiter.
 *
 * Before this key existed the README documented
 * `rateLimit.adapters.<name>.limits.device_verification`, which nothing reads,
 * and the verification endpoint's `device_verification:` prefix fell through
 * to the adapter's 60/60s default. The tests here pin both ends: the schema
 * boundary (defaults and bounds) and the documented key in `reference.conf`
 * resolving, through the real HOCON parser and the real limiter module, to a
 * budget of five.
 */

import { fileURLToPath } from "node:url";
import { memoryRateLimiterModule } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { deviceGrantConfigSchema } from "#/module.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../reference.conf", import.meta.url));

describe("oauth.deviceAuthorization.rateLimit — schema boundary", () => {
	it("defaults to RFC 8628 §5.1's five attempts per five minutes", () => {
		// §5.1's worked example: ~34.5 bits is sufficient only where "the
		// rate-limiting interval and validity period would need to only
		// allow 5 attempts". Five minutes is half the default code lifetime.
		const parsed = deviceGrantConfigSchema.parse({
			oauth: { deviceAuthorization: { enabled: false } },
		});
		expect(parsed.oauth.deviceAuthorization.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("applies the same default when the whole section is omitted", () => {
		const parsed = deviceGrantConfigSchema.parse({ oauth: {} });
		expect(parsed.oauth.deviceAuthorization.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("accepts an operator's own budget", () => {
		const parsed = deviceGrantConfigSchema.parse({
			oauth: { deviceAuthorization: { rateLimit: { limit: 3, windowSeconds: 600 } } },
		});
		expect(parsed.oauth.deviceAuthorization.rateLimit).toEqual({ limit: 3, windowSeconds: 600 });
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a negative limit", { limit: -5, windowSeconds: 300 }],
		["a fractional limit", { limit: 2.5, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a missing field", { limit: 5 }],
	])("refuses %s at the config boundary", (_label, rateLimit) => {
		// A zero here is not "no limit" — it is what an empty environment
		// variable coerces to, and a zero-attempt budget locks every user out
		// while a zero window is not a window. Both fail boot, loudly.
		const result = deviceGrantConfigSchema.safeParse({
			oauth: { deviceAuthorization: { rateLimit } },
		});
		expect(result.success).toBe(false);
	});
});

describe("oauth.deviceAuthorization.rateLimit — the documented key resolves", () => {
	it("reaches the limiter as a budget of five from reference.conf alone", async () => {
		// End to end through what a deployment actually runs: the shipped
		// HOCON defaults, the schema, and the memory limiter module's seed.
		// The sixth attempt under the verification prefix is the one refused.
		const parsed = validate(parseFile(REFERENCE_CONF), deviceGrantConfigSchema);
		expect(parsed.oauth.deviceAuthorization.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });

		const provide = memoryRateLimiterModule.provides?.rateLimiter as (deps: unknown) => {
			check(
				key: string,
				ctx: Record<string, unknown>,
			): Promise<{ allowed: boolean; limit?: number }>;
		};
		const limiter = provide({
			config: {
				...parsed,
				memoryRateLimiter: {
					limits: {},
					defaultLimit: { limit: 60, windowSeconds: 60 },
					maxBuckets: 10_000,
				},
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
		expect(advertised).toBe(5);
		expect(outcomes).toEqual([true, true, true, true, true, false]);
	});
});
