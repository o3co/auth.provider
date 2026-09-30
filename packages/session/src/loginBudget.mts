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
 * The budget `POST /session/login` is limited by, as the session module
 * contributes it for every limiter to read.
 */

import {
	configuredNumber,
	isUsableRateLimitSpec,
	type RateLimitSpec,
	shownConfigValue,
} from "@o3co/auth-provider-core";

/** The key prefix `/session/login` limits under (`login:ip:<ip>`). No `:`. */
export const LOGIN_RATE_LIMIT_PREFIX = "login";

/**
 * `rateLimit.login` (`{ windowMs, limit }`, the window in milliseconds) as a
 * limiter's budget, the window in whole seconds: a sub-second window rounds up
 * to one, since a zero window is not a window. `null` when the configuration
 * gives no `rateLimit.login`: the prefix then falls to the limiter's
 * `defaultLimit`.
 *
 * Each field is read as the schema's `z.coerce.number()` reads it, since
 * HOCON substitutes an environment variable as a string. A value given that
 * no limiter can apply is a `RangeError` naming `rateLimit.login`, a
 * hand-built configuration included: skipped, the endpoint that resists
 * password guessing would run on the limiter's default.
 */
export function readLoginRateLimitBudget(config: unknown): RateLimitSpec | null {
	const login = (config as { rateLimit?: { login?: unknown } } | undefined)?.rateLimit?.login;
	if (login === undefined) return null;
	const { windowMs, limit } =
		typeof login === "object" && login !== null
			? (login as { windowMs?: unknown; limit?: unknown })
			: { windowMs: undefined, limit: undefined };
	const ms = configuredNumber(windowMs);
	const spec = {
		limit: configuredNumber(limit),
		windowSeconds: ms !== undefined && ms > 0 ? Math.max(1, Math.ceil(ms / 1000)) : Number.NaN,
	};
	if (!isUsableRateLimitSpec(spec)) {
		throw new RangeError(
			`rateLimit.login must be { windowMs, limit }: windowMs a positive number of milliseconds and limit a positive whole number, with a window that ends within the Date range (got windowMs ${shownConfigValue(windowMs)}, limit ${shownConfigValue(limit)})`,
		);
	}
	return { limit: spec.limit, windowSeconds: spec.windowSeconds };
}
