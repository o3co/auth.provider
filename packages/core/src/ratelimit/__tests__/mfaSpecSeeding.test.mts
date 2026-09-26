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
 * The MFA budgets a shared limiter resolves by prefix (the MFA ADR's D21):
 * `mfa`, the flood guard on every `/session/mfa` POST, from
 * `mfa.rateLimit.routes` (reference default 60 per 300 s); and `mfa-email`,
 * the sends to one subject, from `mfa.factors.email.sendLimit` (5 per
 * 3600 s). Their budgets live in the MFA section, so a limiter would serve
 * its own default for them unless they are seeded — the gap `login` (#270),
 * `device_verification` (#448) and `webauthn-authentication-options` closed
 * the same way. An operator's own entry for a prefix wins; a key not given
 * seeds nothing; a key given but unusable is refused, naming the key.
 */

import { describe, expect, it } from "vitest";
import {
	MFA_EMAIL_RATE_LIMIT_PREFIX,
	MFA_RATE_LIMIT_PREFIX,
	resolveMfaLimitSpecs,
} from "#/ratelimit/mfaSpec.mjs";
import { resolveSeededLimitSpecs } from "#/ratelimit/seededSpecs.mjs";

const configured = (routes: unknown, sendLimit?: unknown) => ({
	mfa: {
		rateLimit: { routes },
		...(sendLimit === undefined ? {} : { factors: { email: { sendLimit } } }),
	},
});

describe("resolveMfaLimitSpecs", () => {
	it("names the prefixes the MFA routes and email sends key on, neither with a colon", () => {
		expect(MFA_RATE_LIMIT_PREFIX).toBe("mfa");
		expect(MFA_EMAIL_RATE_LIMIT_PREFIX).toBe("mfa-email");
	});

	it("seeds mfa from mfa.rateLimit.routes and mfa-email from mfa.factors.email.sendLimit", () => {
		const limits = resolveMfaLimitSpecs(
			{},
			configured({ limit: 60, windowSeconds: 300 }, { limit: 5, windowSeconds: 3600 }),
		);
		expect(limits[MFA_RATE_LIMIT_PREFIX]).toEqual({ limit: 60, windowSeconds: 300 });
		expect(limits[MFA_EMAIL_RATE_LIMIT_PREFIX]).toEqual({ limit: 5, windowSeconds: 3600 });
	});

	it("leaves an operator-declared spec for either prefix alone", () => {
		const declared = {
			[MFA_RATE_LIMIT_PREFIX]: { limit: 10, windowSeconds: 60 },
			[MFA_EMAIL_RATE_LIMIT_PREFIX]: { limit: 1, windowSeconds: 60 },
		};
		const limits = resolveMfaLimitSpecs(
			declared,
			configured({ limit: 60, windowSeconds: 300 }, { limit: 5, windowSeconds: 3600 }),
		);
		expect(limits).toEqual(declared);
	});

	it("preserves every other prefix, and does not mutate what it was handed", () => {
		const input = { token: { limit: 100, windowSeconds: 60 } };
		const limits = resolveMfaLimitSpecs(input, configured({ limit: 60, windowSeconds: 300 }));
		expect(limits.token).toEqual({ limit: 100, windowSeconds: 60 });
		expect(input).toEqual({ token: { limit: 100, windowSeconds: 60 } });
	});

	it("seeds nothing for a key that is not given — the MFA package not loaded", () => {
		for (const config of [
			{},
			{ mfa: { mode: "off" } },
			{ mfa: { rateLimit: {} } },
			{ mfa: { factors: { email: {} } } },
		]) {
			const limits = resolveMfaLimitSpecs({}, config);
			expect(limits[MFA_RATE_LIMIT_PREFIX], JSON.stringify(config)).toBeUndefined();
			expect(limits[MFA_EMAIL_RATE_LIMIT_PREFIX], JSON.stringify(config)).toBeUndefined();
		}
	});

	it("refuses a budget that is given but unusable, with a RangeError naming the key", () => {
		for (const [routes, key] of [
			[{ limit: 0, windowSeconds: 300 }, /^mfa\.rateLimit\.routes must be/],
			[{ limit: 60, windowSeconds: 1e13 }, /^mfa\.rateLimit\.routes must be/],
			[{ limit: "sixty", windowSeconds: 300 }, /^mfa\.rateLimit\.routes must be/],
			[null, /^mfa\.rateLimit\.routes must be/],
		] as const) {
			expect(() => resolveMfaLimitSpecs({}, configured(routes)), JSON.stringify(routes)).toThrow(
				RangeError,
			);
			expect(() => resolveMfaLimitSpecs({}, configured(routes))).toThrow(key);
		}
		for (const sendLimit of [
			{ limit: 5, windowSeconds: 0 },
			{ limit: 1.5, windowSeconds: 3600 },
			"5",
		]) {
			expect(
				() => resolveMfaLimitSpecs({}, configured({ limit: 60, windowSeconds: 300 }, sendLimit)),
				JSON.stringify(sendLimit),
			).toThrow(/^mfa\.factors\.email\.sendLimit must be/);
		}
	});

	it("reads each key as a schema that coerces would: a numeric string is its number", () => {
		const limits = resolveMfaLimitSpecs(
			{},
			configured({ limit: "60", windowSeconds: "300" }, { limit: "5", windowSeconds: "3600" }),
		);
		expect(limits[MFA_RATE_LIMIT_PREFIX]).toEqual({ limit: 60, windowSeconds: 300 });
		expect(limits[MFA_EMAIL_RATE_LIMIT_PREFIX]).toEqual({ limit: 5, windowSeconds: 3600 });
	});

	it("is one of the seeds every bundled limiter applies", () => {
		const limits = resolveSeededLimitSpecs(
			{},
			configured({ limit: 60, windowSeconds: 300 }, { limit: 5, windowSeconds: 3600 }),
		);
		expect(limits[MFA_RATE_LIMIT_PREFIX]).toEqual({ limit: 60, windowSeconds: 300 });
		expect(limits[MFA_EMAIL_RATE_LIMIT_PREFIX]).toEqual({ limit: 5, windowSeconds: 3600 });
	});
});
