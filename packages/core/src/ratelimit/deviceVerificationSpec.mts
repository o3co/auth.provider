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
import { isUsableRateLimitSpec, requireUsableConfiguredRateLimitSpec } from "./usableSpec.mjs";

/**
 * The key prefix `POST /oauth/device/verification` limits under
 * (`device_verification:user:<subject>`). Defined here, in core, so the seed
 * below and the endpoint that keys on it share one name;
 * `@o3co/auth-provider-device-grant` re-exports it rather than restating it.
 */
export const DEVICE_VERIFICATION_RATE_LIMIT_PREFIX = "device_verification";

/**
 * Is `value` a budget the verification endpoint can be limited by — a
 * positive whole `limit` and `windowSeconds`, the window ending within the
 * Date range?
 *
 * It is `isUsableRateLimitSpec` itself, the predicate every limiter adapter
 * judges a spec by, under the name #448 gave it. The seed below and
 * `deviceGrantModule` both refuse anything else, with the one message
 * `requireUsableConfiguredRateLimitSpec` gives; with two definitions they
 * could answer differently for the same input, and the gap between them is a
 * deployment whose boot refusal reasons from five attempts while the limiter
 * applies sixty. A second definition here was that gap for a window past the
 * Date range: the module mounted, and the limiter refused the seeded spec
 * under its own name rather than this key's.
 * `docs/design-vocabulary.md` maps the concept, and the drift guard keeps a
 * second definition from appearing.
 *
 * `0` is what an empty environment variable coerces to; a zero-attempt
 * budget locks every user out and a zero window is not a window. Both are
 * refused for the same reason the device-grant schema refuses them.
 */
export const isDeviceVerificationRateLimitSpec: (value: unknown) => value is RateLimitSpec =
	isUsableRateLimitSpec;

/**
 * Seed a rate-limiter adapter's `limits` with the device-verification spec
 * drawn from `config.oauth.deviceAuthorization.rateLimit`.
 *
 * RFC 8628 §5.1 sizes the user code's entropy *against* a rate limit — its
 * worked example reaches 2^-32 only where "the rate-limiting interval and
 * validity period would need to only allow 5 attempts" — and the device-grant
 * module refuses to boot without a limiter on exactly that argument. But the
 * adapters resolve a spec by key prefix from their own `limits` map, and
 * nothing seeded `device_verification`, so the key fell through to the
 * adapter's `defaultLimit` of 60/60s: twelve times the budget the boot
 * refusal reasons from, silently, on the one endpoint whose whole job is
 * resisting code guessing. The package README meanwhile documented a key that
 * nothing read.
 *
 * Same shape as `resolveLoginLimitSpec` (#270): one config key that is the
 * source of truth, seeded into each adapter unless the operator declared the
 * prefix explicitly — an explicit `limits.device_verification` is a statement
 * about this adapter and wins.
 *
 * A key that is not given (the section absent, the device-grant package not
 * loaded) seeds nothing. A key that is given is read as core's schema coerces
 * it (a numeric string is its number) and judged by the one predicate, even
 * though the schema validates it: a hand-built config never passed that
 * schema, and it is still a configuration someone wrote. One the predicate
 * refuses (`0`, `"five"`, a blank string, a window past the Date range) is a
 * `RangeError` naming `oauth.deviceAuthorization.rateLimit`, whether or not an
 * explicit entry would have won; it used to be skipped, and the route ran on
 * the adapter's default instead.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only
 *                `oauth.deviceAuthorization.rateLimit` is read).
 */
export const resolveDeviceVerificationLimitSpec = (
	limits: Readonly<Record<string, RateLimitSpec>>,
	config: unknown,
): Record<string, RateLimitSpec> => {
	const result: Record<string, RateLimitSpec> = { ...limits };
	const given = (
		config as { oauth?: { deviceAuthorization?: { rateLimit?: unknown } } } | undefined
	)?.oauth?.deviceAuthorization?.rateLimit;
	if (given === undefined) return result;
	const spec = requireUsableConfiguredRateLimitSpec("oauth.deviceAuthorization.rateLimit", given);
	if (result[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX] !== undefined) return result;

	result[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX] = spec;
	return result;
};
