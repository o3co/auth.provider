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
 * The login's own attempt limit, `session.rateLimit.login` read as the spec
 * the attempt guard counts against, its window rounded up to whole seconds;
 * and the `login` prefix the module claims of the rate limiter with no
 * budget, since no limiter decides the login's limit.
 */

import { describe, expect, it } from "vitest";
import { LOGIN_ATTEMPT_TAG, readLoginAttemptSpec } from "#/loginAttempts.mjs";
import { sessionModule } from "#/module.mjs";

describe("readLoginAttemptSpec", () => {
	it("is session.rateLimit.login, its window in whole seconds", () => {
		expect(
			readLoginAttemptSpec({ rateLimit: { login: { windowMs: 900_000, limit: 20 } } }),
		).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("rounds a window that is not whole seconds up, to one second at least", () => {
		expect(readLoginAttemptSpec({ rateLimit: { login: { windowMs: 1_001, limit: 3 } } })).toEqual({
			limit: 3,
			windowSeconds: 2,
		});
		expect(readLoginAttemptSpec({ rateLimit: { login: { windowMs: 1, limit: 3 } } })).toEqual({
			limit: 3,
			windowSeconds: 1,
		});
	});

	it("takes a day, the longest window a counter takes", () => {
		expect(
			readLoginAttemptSpec({ rateLimit: { login: { windowMs: 86_400_000, limit: 3 } } }),
		).toEqual({ limit: 3, windowSeconds: 86_400 });
	});

	it("reads the key as its schema does: a numeric string is its number", () => {
		expect(
			readLoginAttemptSpec({ rateLimit: { login: { windowMs: "900000", limit: "20" } } }),
		).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("refuses a missing or unusable session.rateLimit.login, naming the key", () => {
		for (const section of [
			undefined,
			{},
			{ rateLimit: {} },
			...[
				{ windowMs: 0, limit: 20 },
				{ windowMs: 86_400_001, limit: 20 },
				{ windowMs: 900_000, limit: 0 },
				{ windowMs: 900_000, limit: 1.5 },
				{ windowMs: Number.NaN, limit: 20 },
				{ windowMs: -900_000, limit: 20 },
				{ windowMs: 900_000, limit: "twenty" },
				{ windowMs: true, limit: 20 },
				null,
				"20/900000",
			].map((login) => ({ rateLimit: { login } })),
		]) {
			expect(() => readLoginAttemptSpec(section), JSON.stringify(section)).toThrow(
				/^session\.rateLimit\.login must be/,
			);
		}
	});

	it("says what it was given, with each value's type", () => {
		expect(() =>
			readLoginAttemptSpec({ rateLimit: { login: { windowMs: 900_000, limit: "twenty" } } }),
		).toThrow(/\(got windowMs 900000, limit "twenty"\)$/);
	});
});

describe("the session module and the rate limiter", () => {
	it("claims the login prefix with no budget: the login's limit is its own", async () => {
		const claim = sessionModule.contributes?.rateLimitBudgets?.[LOGIN_ATTEMPT_TAG];
		expect(claim).toBeTypeOf("function");
		expect(
			await claim?.({ section: { rateLimit: { login: { windowMs: 60_000, limit: 7 } } } } as never),
		).toBeNull();
	});

	it("declares the prefix a verifier's own limit, made at session.rateLimit.login", () => {
		const claim = sessionModule.contributes?.rateLimitBudgets?.[LOGIN_ATTEMPT_TAG];
		expect(claim?.verifier).toEqual({ setting: "session.rateLimit.login" });
	});

	it("reads the attemptCounter slot, and no rateLimiter", () => {
		expect(sessionModule.optional).toContain("attemptCounter");
		expect(sessionModule.optional).not.toContain("rateLimiter");
		expect(sessionModule.requires).not.toContain("rateLimiter");
	});
});
