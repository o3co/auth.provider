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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { RateLimitFailMode } from "./guard.mjs";

export interface RateLimitContext {
	readonly ip?: string;
	readonly userAgent?: string;
	readonly clientId?: string;
	readonly userId?: string;
}

export interface RateLimitDecision {
	readonly allowed: boolean;
	readonly remaining?: number;
	readonly resetAt?: Date;
	/**
	 * Why a refusal was made, for a person: the guard sends it as the 429's
	 * `error_description`, within RFC 6749's characters (`?` for any other),
	 * and sends `Rate limit exceeded` when it is absent, empty or not a string.
	 */
	readonly reason?: string;
	/**
	 * The limit the adapter actually applied to this key. It can differ from
	 * the caller's: an operator's `limits.login` on the adapter overrides the
	 * budget the session module contributes from `rateLimit.login`, and a key
	 * nothing budgets falls to `defaultLimit`. RFC 9239 `RateLimit-*` headers must report what was
	 * enforced. Optional; callers then fall back to their configured value.
	 */
	readonly limit?: number;
}

/**
 * Adapter primitive for rate-limiting decisions.
 */
export interface RateLimiter {
	readonly kind: string;
	/**
	 * The limiter's outage policy: what the guard does when `check` throws
	 * (`"open"` lets the request through, `"closed"` answers `503`), logged and
	 * audited either way. It belongs to the limiter because only its backend can
	 * be down. Absent (as on the in-process limiter) means `closed`, the
	 * `rateLimit.failMode` default. Not read yet: the guard and its callers
	 * still take the policy from `rateLimit.failMode`.
	 */
	readonly failMode?: RateLimitFailMode;
	/**
	 * Atomic check + increment. Key is endpoint-specific (e.g.,
	 * "login:ip:1.2.3.4", "token:client:abc").
	 */
	check(key: string, ctx: RateLimitContext): Promise<RateLimitDecision>;
}

export type RateLimiterFactory = AdapterFactory<RateLimiter>;

/**
 * Rate-limit spec, e.g., `{ limit: 10, windowSeconds: 60 }`. Consumed by
 * built-in adapters; custom adapters may interpret the config freely.
 */
export interface RateLimitSpec {
	readonly limit: number;
	readonly windowSeconds: number;
}

// ---------------------------------------------------------------------------
// ComponentMap slot: `rateLimiter`, optional in oauthModule, so
// `deps.rateLimiter` is `RateLimiter | undefined`. Absent, oauth routes apply
// no rate limiting.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly rateLimiter?: RateLimiter;
	}
}
