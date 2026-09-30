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
 * The WebAuthn module's `webauthn-authentication-options` budget: the
 * unauthenticated options route writes a challenge per request, and its
 * budget lives in the WebAuthn section. The module contributes
 * `webauthn.rateLimit.authenticationOptions` as a `rateLimitBudgets` entry
 * for every limiter to read; without it a shared limiter would serve the
 * route its `defaultLimit`.
 */

import type { RateLimitSpec } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { webauthnModule } from "../module.mjs";
import { WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG } from "../routes/authenticationOptions.mjs";

/** What the module contributes for its options route, from the `webauthn` section. */
const optionsBudget = async (section: unknown): Promise<RateLimitSpec | null | undefined> =>
	webauthnModule.contributes?.rateLimitBudgets?.[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]?.({
		section,
	} as never);

const configured = (authenticationOptions: unknown) => ({ rateLimit: { authenticationOptions } });

describe("the WebAuthn module's options-route budget", () => {
	it("is keyed by the prefix the route limits under, which holds no colon", () => {
		expect(WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG).toBe("webauthn-authentication-options");
	});

	it("is webauthn.rateLimit.authenticationOptions", async () => {
		expect(await optionsBudget(configured({ limit: 30, windowSeconds: 60 }))).toEqual({
			limit: 30,
			windowSeconds: 60,
		});
	});

	it("is switched off when the section gives no budget", async () => {
		for (const section of [undefined, {}, { rateLimit: {} }]) {
			expect(await optionsBudget(section), JSON.stringify(section)).toBeNull();
		}
	});

	it("reads the key as the package's schema does: a numeric string is its number", async () => {
		// `reference.conf` fills both fields from environment variables, which
		// HOCON substitutes as strings, and the section's schema checks nothing.
		expect(await optionsBudget(configured({ limit: "30", windowSeconds: "60" }))).toEqual({
			limit: 30,
			windowSeconds: 60,
		});
	});

	it("refuses a budget that is given but unusable, naming the key", async () => {
		for (const authenticationOptions of [
			{ limit: 30, windowSeconds: 0 },
			{ limit: 0, windowSeconds: 60 },
			{ limit: 1.5, windowSeconds: 60 },
			{ limit: "thirty", windowSeconds: 60 },
			{ limit: "", windowSeconds: 60 },
			{ limit: 30, windowSeconds: 1e13 },
			null,
		]) {
			await expect(
				optionsBudget(configured(authenticationOptions)),
				JSON.stringify(authenticationOptions),
			).rejects.toThrow(/^webauthn\.rateLimit\.authenticationOptions must be/);
		}
	});
});
