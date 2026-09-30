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
 * The verification endpoint's budget, as the device-grant module contributes
 * it for every limiter to read. RFC 8628 §5.1 sizes the user code's entropy
 * against a rate limit (2^-32 only where the interval "would need to only
 * allow 5 attempts"), so this budget, not a limiter's `defaultLimit`, is the
 * one the endpoint must run on.
 */

import {
	isUsableRateLimitSpec,
	type RateLimitSpec,
	requireUsableConfiguredRateLimitSpec,
} from "@o3co/auth-provider-core";

/**
 * The key prefix `POST /oauth/device/verification` limits under
 * (`device_verification:user:<subject>`). No `:`.
 */
export const DEVICE_VERIFICATION_RATE_LIMIT_PREFIX = "device_verification";

/**
 * Is `value` a budget the verification endpoint can be limited by: a positive
 * whole `limit` and `windowSeconds`, the window ending within the Date range?
 *
 * It is core's `isUsableRateLimitSpec` itself, the predicate every limiter
 * judges a spec by. The budget this module contributes and its boot refusal
 * both refuse anything else with the message
 * `requireUsableConfiguredRateLimitSpec` gives. A second definition could
 * answer differently for the same input, leaving a boot refusal that reasons
 * from five attempts while the limiter applies sixty;
 * `docs/design-vocabulary.md` maps the concept and the drift guard keeps a
 * second definition from appearing.
 *
 * `0` is what an empty environment variable coerces to: a zero-attempt budget
 * locks every user out, and a zero window is not a window.
 */
export const isDeviceVerificationRateLimitSpec: (value: unknown) => value is RateLimitSpec =
	isUsableRateLimitSpec;

/**
 * `oauth.deviceAuthorization.rateLimit` as the `device_verification` budget,
 * or `null` when the section gives none: the prefix then falls to the
 * limiter's `defaultLimit`. Each field is read as a coercing schema reads it;
 * a budget given that no limiter can apply is a `RangeError` naming the key,
 * a hand-built configuration included.
 */
export function readVerificationRateLimitBudget(
	section: { readonly rateLimit?: unknown } | undefined,
): RateLimitSpec | null {
	const given = section?.rateLimit;
	if (given === undefined) return null;
	return requireUsableConfiguredRateLimitSpec("oauth.deviceAuthorization.rateLimit", given);
}
