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
 * `POST /session/login`'s own attempt limit: the tag its attempts are counted
 * under (`login:ip:<ip>`), and `session.rateLimit.login` read as the spec the
 * attempt guard counts them against. The limit is the session module's alone:
 * no rate limiter's budget, failMode or outage changes it.
 */

import {
	type AttemptSpec,
	configuredNumber,
	isAttemptSpec,
	MAX_ATTEMPT_WINDOW_SECONDS,
	shownConfigValue,
} from "@o3co/auth-provider-core";

/** The tag `/session/login` counts attempts under, and the rate-limit prefix the module claims. No `:`. */
export const LOGIN_ATTEMPT_TAG = "login";

/** The longest `session.rateLimit.login.windowMs`: the longest window a counter takes. */
export const MAX_LOGIN_WINDOW_MS = MAX_ATTEMPT_WINDOW_SECONDS * 1000;

/**
 * `session.rateLimit.login` (`{ windowMs, limit }`) as an attempt spec, the
 * window rounded up to whole seconds, so a window is never shorter than
 * configured. Fields read as the schema coerces them; a missing or unusable
 * value is a `RangeError` naming the key.
 */
export function readLoginAttemptSpec(section: unknown): AttemptSpec {
	const login = (section as { rateLimit?: { login?: unknown } } | undefined)?.rateLimit?.login;
	const { windowMs, limit } =
		typeof login === "object" && login !== null
			? (login as { windowMs?: unknown; limit?: unknown })
			: { windowMs: undefined, limit: undefined };
	const ms = configuredNumber(windowMs);
	const spec = {
		limit: configuredNumber(limit),
		windowSeconds:
			ms !== undefined && Number.isInteger(ms) && ms > 0 && ms <= MAX_LOGIN_WINDOW_MS
				? Math.ceil(ms / 1000)
				: Number.NaN,
	};
	if (!isAttemptSpec(spec)) {
		throw new RangeError(
			`session.rateLimit.login must be { windowMs, limit }: windowMs a whole number of milliseconds from 1 to ${MAX_LOGIN_WINDOW_MS} and limit a positive whole number (got windowMs ${shownConfigValue(windowMs)}, limit ${shownConfigValue(limit)})`,
		);
	}
	return { limit: spec.limit, windowSeconds: spec.windowSeconds };
}
