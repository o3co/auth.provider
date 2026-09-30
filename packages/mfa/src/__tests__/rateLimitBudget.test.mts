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
 * The MFA module's `mfa` budget: every `/session/mfa` POST limits under the
 * `mfa` prefix (`mfa:ip:<ip>`), the flood guard of ADR
 * 2026-09-25-multi-factor-authentication, and its budget is
 * `mfa.rateLimit.routes`. The module contributes it as a `rateLimitBudgets`
 * entry for every limiter to read.
 */

import type { RateLimitSpec } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { MFA_RATE_LIMIT_PREFIX } from "#/index.mjs";
import { mfaModule } from "#/module.mjs";
import { boot, configFor, disposeAll, refusal } from "./moduleHarness.mjs";

afterEach(disposeAll);

/** What the MFA module contributes for its routes' prefix, from the `mfa` section. */
const routesBudget = async (section: unknown): Promise<RateLimitSpec | null | undefined> =>
	mfaModule().contributes?.rateLimitBudgets?.[MFA_RATE_LIMIT_PREFIX]?.({ section } as never);

const configured = (routes: unknown) => ({ rateLimit: { routes } });

describe("the MFA module's routes budget", () => {
	it("is keyed by the prefix the MFA routes limit under, which holds no colon", () => {
		expect(MFA_RATE_LIMIT_PREFIX).toBe("mfa");
	});

	it("is the one budget the module contributes", () => {
		expect(Object.keys(mfaModule().contributes?.rateLimitBudgets ?? {})).toEqual([
			MFA_RATE_LIMIT_PREFIX,
		]);
	});

	it("is mfa.rateLimit.routes", async () => {
		expect(await routesBudget(configured({ limit: 60, windowSeconds: 300 }))).toEqual({
			limit: 60,
			windowSeconds: 300,
		});
	});

	it("is switched off when the section gives no budget", async () => {
		for (const section of [undefined, {}, { rateLimit: {} }]) {
			expect(await routesBudget(section), JSON.stringify(section)).toBeNull();
		}
	});

	it("reads the key as a coercing schema does: a numeric string is its number", async () => {
		expect(await routesBudget(configured({ limit: "60", windowSeconds: "300" }))).toEqual({
			limit: 60,
			windowSeconds: 300,
		});
	});

	it("refuses a budget that is given but unusable, naming the key", async () => {
		for (const routes of [
			{ limit: 0, windowSeconds: 300 },
			{ limit: 60, windowSeconds: 0 },
			{ limit: 60, windowSeconds: 1e13 },
			{ limit: "sixty", windowSeconds: 300 },
			{ limit: 1.5, windowSeconds: 300 },
			null,
		]) {
			await expect(routesBudget(configured(routes)), JSON.stringify(routes)).rejects.toThrow(
				/^mfa\.rateLimit\.routes must be/,
			);
		}
	});
});

describe("the MFA module's routes budget, through createApp", () => {
	it("registers mfa.rateLimit.routes as the contributed budget for mfa", async () => {
		const { handle } = await boot({
			config: configFor("optional", { rateLimit: { routes: { limit: 13, windowSeconds: 240 } } }),
		});
		expect(handle.components.rateLimitBudgetResolver?.get(MFA_RATE_LIMIT_PREFIX)).toEqual({
			limit: 13,
			windowSeconds: 240,
		});
	});

	it("refuses to boot on a budget no limiter can apply, naming the key — core's schema lets it through, the module's contribution does not", async () => {
		const err = await refusal({
			config: configFor("optional", { rateLimit: { routes: { limit: 0, windowSeconds: 300 } } }),
		});
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "mfa",
			kind: "rateLimitBudgets",
			name: MFA_RATE_LIMIT_PREFIX,
		});
		expect(err.message).toContain("mfa.rateLimit.routes must be");
	});
});
