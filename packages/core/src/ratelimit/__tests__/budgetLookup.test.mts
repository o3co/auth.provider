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
 * The one lookup both bundled limiters take a key's budget from: the
 * limiter's own `limits` entry for the key's prefix, else the budget the
 * prefix's owner contributed, else the limiter's `defaultLimit`.
 */

import { describe, expect, it } from "vitest";
import type { RateLimitBudgetResolver } from "#/modules/manifest/index.mjs";
import { createRateLimitBudgetLookup } from "#/ratelimit/budgetLookup.mjs";
import type { RateLimitSpec } from "#/ratelimit/types.mjs";

const DEFAULT: RateLimitSpec = { limit: 60, windowSeconds: 60 };

/** A resolver over `budgets`, recording every prefix it is asked for. */
function resolverOver(budgets: Record<string, RateLimitSpec>): RateLimitBudgetResolver & {
	readonly asked: string[];
} {
	const asked: string[] = [];
	return {
		asked,
		get: (prefix) => {
			asked.push(prefix);
			return Object.hasOwn(budgets, prefix) ? budgets[prefix] : undefined;
		},
		entries: () => new Map(Object.entries(budgets)).entries(),
	};
}

describe("createRateLimitBudgetLookup", () => {
	it("answers the limiter's own limits entry for the key's prefix, over a contributed budget", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { login: { limit: 4, windowSeconds: 45 } },
			defaultLimit: DEFAULT,
			budgets: resolverOver({ login: { limit: 20, windowSeconds: 900 } }),
		});

		expect(lookup("login:ip:192.0.2.1")).toEqual({
			prefix: "login",
			spec: { limit: 4, windowSeconds: 45 },
		});
	});

	it("answers the contributed budget for a prefix the limiter's limits do not declare", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { token: { limit: 120, windowSeconds: 60 } },
			defaultLimit: DEFAULT,
			budgets: resolverOver({ login: { limit: 20, windowSeconds: 900 } }),
		});

		expect(lookup("login:ip:192.0.2.1").spec).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("answers defaultLimit for a prefix nothing budgets", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: {},
			defaultLimit: DEFAULT,
			budgets: resolverOver({ login: { limit: 20, windowSeconds: 900 } }),
		});

		expect(lookup("introspect:ip:192.0.2.1").spec).toEqual(DEFAULT);
	});

	it("answers defaultLimit when no resolver is given", () => {
		const lookup = createRateLimitBudgetLookup("test", { defaultLimit: DEFAULT });

		expect(lookup("login:ip:192.0.2.1").spec).toEqual(DEFAULT);
	});

	it("reads the resolver at each lookup, never when it is built", () => {
		const budgets: Record<string, RateLimitSpec> = {};
		const resolver = resolverOver(budgets);
		const lookup = createRateLimitBudgetLookup("test", {
			defaultLimit: DEFAULT,
			budgets: resolver,
		});
		expect(resolver.asked).toEqual([]);

		budgets.mfa = { limit: 13, windowSeconds: 240 };

		expect(lookup("mfa:ip:192.0.2.1").spec).toEqual({ limit: 13, windowSeconds: 240 });
		expect(resolver.asked).toEqual(["mfa"]);
	});

	it.each([
		["an empty object", {}],
		["a NaN limit", { limit: Number.NaN, windowSeconds: 60 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a string limit", { limit: "5", windowSeconds: 60 }],
	])(
		"throws for a key whose resolver answers %s, naming the caller and the prefix",
		(_label, answered) => {
			const lookup = createRateLimitBudgetLookup("createExampleLimiter", {
				defaultLimit: DEFAULT,
				budgets: {
					get: () => answered as RateLimitSpec,
					entries: () => new Map<string, RateLimitSpec>().entries(),
				},
			});
			expect(() => lookup("mfa:ip:192.0.2.1")).toThrow(RangeError);
			expect(() => lookup("mfa:ip:192.0.2.1")).toThrow(/^createExampleLimiter: .*"mfa"/);
		},
	);

	it("takes the prefix up to the first colon, and a key with none whole", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { plain: { limit: 3, windowSeconds: 30 } },
			defaultLimit: DEFAULT,
		});

		expect(lookup("device_verification:user:a:b").prefix).toBe("device_verification");
		expect(lookup("plain")).toEqual({ prefix: "plain", spec: { limit: 3, windowSeconds: 30 } });
	});

	it("holds the limits and the default as they were checked: a later change to the caller's objects reaches no lookup", () => {
		const limits: Record<string, { limit: number; windowSeconds: number }> = {
			token: { limit: 5, windowSeconds: 60 },
		};
		const defaultLimit = { limit: 60, windowSeconds: 60 };
		const lookup = createRateLimitBudgetLookup("test", { limits, defaultLimit });

		limits.token.limit = 0;
		limits.login = { limit: 1, windowSeconds: 1 };
		defaultLimit.windowSeconds = 0;

		expect(lookup("token:ip:192.0.2.1").spec).toEqual({ limit: 5, windowSeconds: 60 });
		expect(lookup("login:ip:192.0.2.1").spec).toEqual({ limit: 60, windowSeconds: 60 });
	});

	it("hands out specs no caller can change: the next lookup applies the one it checked", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { token: { limit: 5, windowSeconds: 60 } },
			defaultLimit: DEFAULT,
		});
		for (const key of ["token:ip:192.0.2.1", "login:ip:192.0.2.1"]) {
			const { spec } = lookup(key);
			expect(Object.isFrozen(spec), key).toBe(true);
			expect(() => {
				(spec as { limit: number }).limit = 0;
			}, key).toThrow(TypeError);
		}
		expect(lookup("token:ip:192.0.2.1").spec).toEqual({ limit: 5, windowSeconds: 60 });
		expect(lookup("login:ip:192.0.2.1").spec).toEqual(DEFAULT);
	});

	it("refuses, naming the caller, a limits entry or a default no limiter can apply as written", () => {
		expect(() =>
			createRateLimitBudgetLookup("createExampleLimiter", {
				limits: { token: { limit: 5, windowSeconds: 0 } },
				defaultLimit: DEFAULT,
			}),
		).toThrow(/^createExampleLimiter: limits\.token must be/);
		expect(() =>
			createRateLimitBudgetLookup("createExampleLimiter", {
				defaultLimit: { limit: 0, windowSeconds: 60 },
			}),
		).toThrow(/^createExampleLimiter: defaultLimit must be/);
	});
});
