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
 * `POST /oauth/device/verification`'s own attempt limit: the tag its attempts
 * are counted under (`device_verification:user:<subject>`), and
 * `device-grant.rateLimit` read as the spec the attempt guard counts them
 * against — the limit RFC 8628 §5.1 sizes the user code against. The limit is
 * the device-grant module's alone: no rate limiter's budget, failMode or
 * outage changes it.
 */

import {
	type AttemptSpec,
	configuredNumber,
	isAttemptSpec,
	MAX_ATTEMPT_WINDOW_SECONDS,
	shownConfigValue,
} from "@o3co/auth-provider-core";

/** The tag the verification endpoint counts attempts under, and the rate-limit prefix the module claims. No `:`. */
export const DEVICE_VERIFICATION_ATTEMPT_TAG = "device_verification";

/**
 * `device-grant.rateLimit` (`{ limit, windowSeconds }`) as an attempt spec.
 * Fields read as the schema coerces them; a missing or unusable value, a
 * window over a day included, is a `RangeError` naming the key.
 */
export function readVerificationAttemptSpec(section: unknown): AttemptSpec {
	const given = (section as { rateLimit?: unknown } | undefined)?.rateLimit;
	const { limit, windowSeconds } =
		typeof given === "object" && given !== null
			? (given as { limit?: unknown; windowSeconds?: unknown })
			: { limit: undefined, windowSeconds: undefined };
	const spec = {
		limit: configuredNumber(limit) ?? Number.NaN,
		windowSeconds: configuredNumber(windowSeconds) ?? Number.NaN,
	};
	if (!isAttemptSpec(spec)) {
		throw new RangeError(
			`device-grant.rateLimit must be { limit, windowSeconds }: limit a positive whole number and windowSeconds a whole number of seconds from 1 to ${MAX_ATTEMPT_WINDOW_SECONDS} (got limit ${shownConfigValue(limit)}, windowSeconds ${shownConfigValue(windowSeconds)})`,
		);
	}
	return { limit: spec.limit, windowSeconds: spec.windowSeconds };
}
