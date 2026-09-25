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

import type { RateLimitSpec } from "./types.mjs";
import { requireUsableConfiguredRateLimitSpec } from "./usableSpec.mjs";

/**
 * The key prefix every `/session/mfa` POST limits under (`mfa:ip:<ip>`), the
 * flood guard of the MFA ADR's D21. Defined in core, beside the seed, so the
 * MFA package's routes and every limiter share one name. Contains no `:`,
 * since an adapter takes the prefix up to the first colon.
 */
export const MFA_RATE_LIMIT_PREFIX = "mfa";

/**
 * The key prefix the email sends to one subject are counted under
 * (`mfa-email:…`), through `checkWithFailMode` (D21). No `:`.
 */
export const MFA_EMAIL_RATE_LIMIT_PREFIX = "mfa-email";

/** One seed: a prefix from one config key, unless the adapter's own limits declare it. */
function seed(
	result: Record<string, RateLimitSpec>,
	prefix: string,
	key: string,
	given: unknown,
): void {
	if (given === undefined) return;
	const spec = requireUsableConfiguredRateLimitSpec(key, given);
	if (result[prefix] !== undefined) return;
	result[prefix] = spec;
}

/**
 * Seed a rate-limiter adapter's `limits` with the MFA budgets: `mfa` from
 * `mfa.rateLimit.routes` (reference default 60 per 300 s) and `mfa-email`
 * from `mfa.factors.email.sendLimit` (5 per 3600 s).
 *
 * Both live in the MFA section, so a shared limiter, which resolves a prefix
 * from its own `limits`, would serve its `defaultLimit` for them unless they
 * are seeded — the gap `resolveLoginLimitSpec` (#270),
 * `resolveDeviceVerificationLimitSpec` (#448) and
 * `resolveWebAuthnAuthenticationOptionsLimitSpec` close for theirs. An
 * operator's explicit entry for a prefix is a statement about this adapter
 * and wins. A key that is not given (no `mfa` section, the MFA package not
 * loaded) seeds nothing. A key that is given is read as a schema that
 * coerces would read it, since `reference.conf` may fill it from environment
 * variables HOCON substitutes as strings, and one the predicate refuses is a
 * `RangeError` naming the key.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only the two keys are read).
 */
export const resolveMfaLimitSpecs = (
	limits: Readonly<Record<string, RateLimitSpec>>,
	config: unknown,
): Record<string, RateLimitSpec> => {
	const result: Record<string, RateLimitSpec> = { ...limits };
	const mfa = (
		config as
			| {
					mfa?: {
						rateLimit?: { routes?: unknown };
						factors?: { email?: { sendLimit?: unknown } };
					};
			  }
			| undefined
	)?.mfa;
	seed(result, MFA_RATE_LIMIT_PREFIX, "mfa.rateLimit.routes", mfa?.rateLimit?.routes);
	seed(
		result,
		MFA_EMAIL_RATE_LIMIT_PREFIX,
		"mfa.factors.email.sendLimit",
		mfa?.factors?.email?.sendLimit,
	);
	return result;
};
