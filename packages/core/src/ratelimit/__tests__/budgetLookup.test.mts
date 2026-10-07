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
 * limiter's own `limits` entry for the key's prefix, else the limiter's
 * `defaultLimit`. Nothing a module contributes takes part.
 */

import { describe, expect, it } from "vitest";
import { createRateLimitBudgetLookup } from "#/ratelimit/budgetLookup.mjs";
import type { RateLimitSpec } from "#/ratelimit/types.mjs";

const DEFAULT: RateLimitSpec = { limit: 60, windowSeconds: 60 };

describe("createRateLimitBudgetLookup", () => {
	it("answers the limiter's own limits entry for the key's prefix", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { login: { limit: 4, windowSeconds: 45 } },
			defaultLimit: DEFAULT,
		});

		expect(lookup("login:ip:192.0.2.1")).toEqual({
			prefix: "login",
			spec: { limit: 4, windowSeconds: 45 },
		});
	});

	it("answers defaultLimit for a prefix the limiter's limits do not declare", () => {
		const lookup = createRateLimitBudgetLookup("test", {
			limits: { token: { limit: 120, windowSeconds: 60 } },
			defaultLimit: DEFAULT,
		});

		expect(lookup("introspect:ip:192.0.2.1").spec).toEqual(DEFAULT);
	});

	it("answers defaultLimit when no limits are given", () => {
		const lookup = createRateLimitBudgetLookup("test", { defaultLimit: DEFAULT });

		expect(lookup("login:ip:192.0.2.1").spec).toEqual(DEFAULT);
	});

	it("reads no budget beside its limits and default: a resolver handed in is never asked", () => {
		const asked: string[] = [];
		const lookup = createRateLimitBudgetLookup("test", {
			defaultLimit: DEFAULT,
			budgets: {
				get: (prefix: string) => {
					asked.push(prefix);
					return { limit: 1, windowSeconds: 60 };
				},
			},
		} as never);

		expect(lookup("mfa:ip:192.0.2.1").spec).toEqual(DEFAULT);
		expect(asked).toEqual([]);
	});

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

	it("reads each limits entry and the default once: an accessor that answers another value later changes nothing it checked", () => {
		const shifting = (good: number): { readonly limit: number; readonly windowSeconds: number } => {
			let reads = 0;
			return {
				get limit(): number {
					reads += 1;
					return reads === 1 ? good : Number.NaN;
				},
				windowSeconds: 60,
			};
		};
		const lookup = createRateLimitBudgetLookup("probe", {
			limits: { login: shifting(5) as RateLimitSpec },
			defaultLimit: shifting(7) as RateLimitSpec,
		});
		expect(lookup("login:1.2.3.4").spec).toEqual({ limit: 5, windowSeconds: 60 });
		expect(lookup("other:1.2.3.4").spec).toEqual({ limit: 7, windowSeconds: 60 });
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

	describe("a prefix named after an Object.prototype member", () => {
		const PROTOTYPE_MEMBERS = [
			"constructor",
			"__proto__",
			"toString",
			"hasOwnProperty",
			"valueOf",
		] as const;

		it.each(PROTOTYPE_MEMBERS)(
			"%s: answers defaultLimit when its limits do not declare it",
			(name) => {
				const lookup = createRateLimitBudgetLookup("test", {
					limits: { login: { limit: 4, windowSeconds: 45 } },
					defaultLimit: DEFAULT,
				});

				expect(lookup(`${name}:ip:192.0.2.1`)).toEqual({ prefix: name, spec: DEFAULT });
			},
		);

		it.each(PROTOTYPE_MEMBERS)("%s: answers the limits entry declared for it", (name) => {
			const lookup = createRateLimitBudgetLookup("test", {
				limits: { [name]: { limit: 2, windowSeconds: 30 } },
				defaultLimit: DEFAULT,
			});

			expect(lookup(`${name}:ip:192.0.2.1`).spec).toEqual({ limit: 2, windowSeconds: 30 });
		});
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
