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
import { configuredNumber, isUsableRateLimitSpec, shownConfigValue } from "./usableSpec.mjs";

/** The key prefix `/session/login` limits under. See `RateLimiter.check`. */
const LOGIN_PREFIX = "login";

/**
 * Seed a rate-limiter adapter's `limits` with the login spec from
 * `config.rateLimit.login` (in milliseconds).
 *
 * `/session/login` runs on the shared `RateLimiter`, keyed `login:ip:<ip>`.
 * Adapters resolve a spec by key prefix from their own `limits`, so an
 * unseeded `login:` key falls to the adapter's `defaultLimit` (60/60s),
 * **weaker** than the documented 20 / 15 min on the endpoint that resists
 * password guessing. Seeding keeps `rateLimit.login` the single source of
 * truth; restating it under each adapter's `limits` would be two numbers that
 * must agree.
 *
 * An operator-declared `limits.login` wins: it is an explicit statement about
 * this adapter.
 *
 * A `rateLimit.login` not given seeds nothing. A given one is read as core's
 * `rateLimit` schema coerces it and judged, after conversion to whole seconds,
 * by the one predicate every limiter uses; one it refuses is a `RangeError`
 * naming `rateLimit.login`, hand-built config included. An operator reading
 * `limits` alone sees no `login` entry while login *is* limited;
 * `reference.conf` documents this beside both `limits` blocks and beside
 * `rateLimit.login`.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only `rateLimit.login` is read).
 */
export const resolveLoginLimitSpec = (
	limits: Readonly<Record<string, RateLimitSpec>>,
	config: unknown,
): Record<string, RateLimitSpec> => {
	const result: Record<string, RateLimitSpec> = { ...limits };
	const login = (config as { rateLimit?: { login?: unknown } } | undefined)?.rateLimit?.login;
	if (login === undefined) return result;

	const { windowMs, limit } =
		typeof login === "object" && login !== null
			? (login as { windowMs?: unknown; limit?: unknown })
			: { windowMs: undefined, limit: undefined };
	// Read as the schema's `z.coerce.number()` reads them: HOCON substitutes
	// an environment variable as a string, and createApp parses `rateLimit`
	// only when `sessionModule` (whose schema picks it) is mounted, so a
	// composition without it hands this the string.
	const ms = configuredNumber(windowMs);
	const spec = {
		limit: configuredNumber(limit),
		// Specs are whole seconds; a sub-second window would round down to 0,
		// and a zero window is not a window.
		windowSeconds: ms !== undefined && ms > 0 ? Math.max(1, Math.ceil(ms / 1000)) : Number.NaN,
	};
	if (!isUsableRateLimitSpec(spec)) {
		throw new RangeError(
			`rateLimit.login must be { windowMs, limit }: windowMs a positive number of milliseconds and limit a positive whole number, with a window that ends within the Date range (got windowMs ${shownConfigValue(windowMs)}, limit ${shownConfigValue(limit)})`,
		);
	}
	if (result[LOGIN_PREFIX] !== undefined) return result;

	result[LOGIN_PREFIX] = { limit: spec.limit, windowSeconds: spec.windowSeconds };
	return result;
};
