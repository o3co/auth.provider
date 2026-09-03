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

/**
 * The key prefix `POST /oauth/device/verification` limits under
 * (`device_verification:user:<subject>`). Defined here, in core, so the seed
 * below and the endpoint that keys on it share one name;
 * `@o3co/auth-provider-device-grant` re-exports it rather than restating it.
 */
export const DEVICE_VERIFICATION_RATE_LIMIT_PREFIX = "device_verification";

const isPositiveInteger = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value > 0;

/**
 * Is `value` a budget the verification endpoint can be limited by — a
 * positive-integer `limit` and `windowSeconds`?
 *
 * The one definition of that shape (#448). The seed below answers "leave the
 * adapter's default in place" for anything else, and `deviceGrantModule`
 * answers "refuse to boot" for anything else; with two definitions those
 * two answers could be given for different inputs, and the gap between them
 * is a deployment whose boot refusal reasons from five attempts while the
 * limiter applies sixty. `docs/design-vocabulary.md` maps the concept here,
 * and the drift guard keeps a second definition from appearing.
 *
 * `0` is what an empty environment variable coerces to; a zero-attempt
 * budget locks every user out and a zero window is not a window. Both are
 * refused for the same reason the device-grant schema refuses them.
 */
export const isDeviceVerificationRateLimitSpec = (value: unknown): value is RateLimitSpec => {
	if (value === null || typeof value !== "object") return false;
	const { limit, windowSeconds } = value as { limit?: unknown; windowSeconds?: unknown };
	return isPositiveInteger(limit) && isPositiveInteger(windowSeconds);
};

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
 * The values are screened with `isDeviceVerificationRateLimitSpec` even
 * though the device-grant schema validates them: a hand-built config never
 * passed that schema, and a limit invented from `0` or `"5"` is worse than
 * the adapter's own default.
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
	if (result[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX] !== undefined) return result;

	const spec = (config as { oauth?: { deviceAuthorization?: { rateLimit?: unknown } } } | undefined)
		?.oauth?.deviceAuthorization?.rateLimit;
	if (!isDeviceVerificationRateLimitSpec(spec)) return result;

	result[DEVICE_VERIFICATION_RATE_LIMIT_PREFIX] = {
		limit: spec.limit,
		windowSeconds: spec.windowSeconds,
	};
	return result;
};
