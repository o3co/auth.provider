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
 * this adapter, and overwriting it would discard what they wrote. The tradeoff
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
	if (result[LOGIN_PREFIX] !== undefined) return result;

	const login = (
		config as { rateLimit?: { login?: { windowMs?: unknown; limit?: unknown } } } | undefined
	)?.rateLimit?.login;
	const windowMs = login?.windowMs;
	const limit = login?.limit;
	// A hand-built config that never passed `CoreConfigSchema` can carry
	// anything. Leaving the adapter's own default in place beats inventing a
	// limit from a value the operator did not really supply.
	if (typeof windowMs !== "number" || !Number.isFinite(windowMs) || windowMs <= 0) return result;
	if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) return result;

	result[LOGIN_PREFIX] = {
		limit,
		// Specs are whole seconds; a sub-second window would round down to 0,
		// and a zero window is not a window.
		windowSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
	};
	return result;
};
