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
 * The `device_verification` budget the device-grant module contributes: the
 * one RFC 8628 §5.1 sizes the user code's entropy against.
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
 * Whether `value` is a budget the verification endpoint can be limited by. It
 * is core's `isUsableRateLimitSpec` itself: one definition, so the boot
 * refusal and the limiter cannot disagree (`docs/design-vocabulary.md`).
 */
export const isDeviceVerificationRateLimitSpec: (value: unknown) => value is RateLimitSpec =
	isUsableRateLimitSpec;

/**
 * `device-grant.rateLimit` as the budget, `null` when not given;
 * read as a coercing schema reads it, and a `RangeError` naming the key when
 * no limiter can apply it.
 */
export function readVerificationRateLimitBudget(
	section: { readonly rateLimit?: unknown } | undefined,
): RateLimitSpec | null {
	const given = section?.rateLimit;
	if (given === undefined) return null;
	return requireUsableConfiguredRateLimitSpec("device-grant.rateLimit", given);
}
