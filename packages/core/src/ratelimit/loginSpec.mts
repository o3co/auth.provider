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
 * Seed a rate-limiter adapter's `limits` with the login spec drawn from
 * `config.rateLimit.login`.
 *
 * `/session/login` runs on the shared `RateLimiter`, keyed `login:ip:<ip>`
 * (#270). Adapters resolve a spec by key prefix from their own `limits` map,
 * but the documented login window and limit live in a different config slice —
 * `rateLimit.login`, in milliseconds. Left unseeded, a `login:` key falls
 * through to the adapter's `defaultLimit` of 60/60s: **weaker** than the
 * documented 20 / 15 min, silently, on the one endpoint whose whole job is
 * resisting password guessing.
 *
 * Seeding keeps `rateLimit.login` the single source of truth. Restating the
 * value under each adapter's `limits` instead would be two numbers that must
 * agree, which is the drift bug rather than a fix for it.
 *
 * An operator-declared `limits.login` wins: that is an explicit statement about
 * this adapter, and overwriting it would discard what they wrote.
 *
 * A `rateLimit.login` that is not given seeds nothing. One that is given is
 * read as `AppConfigSchema`'s `rateLimit` section coerces it (a numeric
 * string is its number) and judged by the one predicate every limiter uses,
 * after the conversion to whole seconds, and one it refuses is a `RangeError`
 * naming `rateLimit.login` — a hand-built config that never passed that
 * schema is still a configuration someone wrote. It used to be
 * skipped, and `/session/login` ran on the adapter's default instead. The tradeoff
 * is that an operator reading `limits` alone sees no `login` entry while login
 * *is* limited — `reference.conf` documents this beside both `limits` blocks
 * and beside `rateLimit.login`.
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
