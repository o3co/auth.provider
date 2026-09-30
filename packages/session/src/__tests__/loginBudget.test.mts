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
 * The session module's `login` budget: `/session/login` limits under the
 * `login` prefix, and its window and limit are `session.rateLimit.login`, in
 * milliseconds. The module contributes it as a `rateLimitBudgets` entry, in
 * whole seconds, for every limiter to read; without it a shared limiter
 * would serve the endpoint that resists password guessing its
 * `defaultLimit` of 60 per 60 s.
 */

import type { RateLimitSpec } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { sessionModule } from "#/module.mjs";

/** What the module contributes for `login`, from its section, `session`. */
const loginBudget = async (section: unknown): Promise<RateLimitSpec | null | undefined> =>
	sessionModule.contributes?.rateLimitBudgets?.login?.({ section } as never);

describe("the session module's login budget", () => {
	it("is session.rateLimit.login, its window in whole seconds", async () => {
		expect(await loginBudget({ rateLimit: { login: { windowMs: 900_000, limit: 20 } } })).toEqual({
			limit: 20,
			windowSeconds: 900,
		});
	});

	it("rounds a sub-second window up to one second", async () => {
		// Specs are whole seconds; rounding down would give 0, and a zero
		// window is not a window.
		expect(await loginBudget({ rateLimit: { login: { windowMs: 500, limit: 3 } } })).toEqual({
			limit: 3,
			windowSeconds: 1,
		});
	});

	it("is switched off when the section gives no rateLimit.login", async () => {
		expect(await loginBudget({})).toBeNull();
		expect(await loginBudget({ rateLimit: {} })).toBeNull();
	});

	it("reads the key as its schema does: a numeric string is its number", async () => {
		// HOCON substitutes an environment variable as a string, and the
		// schema's `z.coerce.number()` takes it.
		expect(
			await loginBudget({ rateLimit: { login: { windowMs: "900000", limit: "20" } } }),
		).toEqual({ limit: 20, windowSeconds: 900 });
		expect(
			await loginBudget({ rateLimit: { login: { windowMs: 900_000, limit: " 20 " } } }),
		).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("refuses a session.rateLimit.login that is given but unusable, naming the key", async () => {
		for (const login of [
			{ windowMs: 0, limit: 20 },
			{ windowMs: 900_000, limit: 0 },
			{ windowMs: 1e19, limit: 20 },
			{ windowMs: 900_000, limit: 1.5 },
			{ windowMs: Number.NaN, limit: 20 },
			{ windowMs: -900_000, limit: 20 },
			{ windowMs: 900_000, limit: "twenty" },
			{ windowMs: 900_000, limit: "" },
			{ windowMs: "  ", limit: 20 },
			{ windowMs: 900_000, limit: true },
			{ windowMs: [900_000], limit: 20 },
			{ windowMs: 900_000, limit: "1.5" },
			null,
			"20/900000",
		]) {
			await expect(loginBudget({ rateLimit: { login } }), JSON.stringify(login)).rejects.toThrow(
				/^session\.rateLimit\.login must be/,
			);
		}
	});

	it("says what it was given, with each value's type", async () => {
		await expect(
			loginBudget({ rateLimit: { login: { windowMs: 900_000, limit: "twenty" } } }),
		).rejects.toThrow(/\(got windowMs 900000, limit "twenty"\)$/);
		await expect(
			loginBudget({ rateLimit: { login: { windowMs: true, limit: 20 } } }),
		).rejects.toThrow(/\(got windowMs true, limit 20\)$/);
	});
});
