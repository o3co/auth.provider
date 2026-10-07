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

/**
 * What the guard does when a limiter's backend errors: `"open"` lets the
 * request through, `"closed"` answers `503`.
 */
export type RateLimitFailMode = "open" | "closed";

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
	 * The limit the adapter actually applied to this key: for a bundled
	 * limiter, its own `limits` entry for the key's prefix, else its
	 * `defaultLimit`. RFC 9239 `RateLimit-*` headers must report what was
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
	 * be down, and the guard reads it from here alone, once, when it is built.
	 * Only absence (as on the in-process limiter, which has no backend) means
	 * `closed`; any other value refuses the guard's or the policy's build.
	 */
	readonly failMode?: RateLimitFailMode;
	/** The budget a key falls to when nothing else covers its prefix. */
	readonly defaultLimit?: RateLimitSpec;
	/**
	 * Atomic check + increment. Key is endpoint-specific (e.g.,
	 * "token:ip:1.2.3.4", "token:client:abc").
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

/**
 * The declared-absence policy of the `rateLimiter` slot, which boot attaches
 * wherever a module reads the slot: a composition that wires no limiter lists
 * `rateLimiter` in `core.declaredAbsent`, or boot refuses. A module that
 * attaches a policy to the slot itself attaches this one.
 */
export const RATE_LIMITER_ABSENCE_POLICY = {
	configKey: ["core", "declaredAbsent"],
	absentValue: "rateLimiter",
	hint:
		"Without a limiter, a route that keys it and has no per-process fallback of its own lets " +
		"each request through: no request-volume limit applies there, unless something in front " +
		"of the provider applies one.",
} as const;

// ---------------------------------------------------------------------------
// ComponentMap slot: `rateLimiter`, optional to wire but not to decide (see
// RATE_LIMITER_ABSENCE_POLICY), so `deps.rateLimiter` is
// `RateLimiter | undefined`. Absent, a route that keys it passes requests
// through unless its module falls back to a per-process limiter.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly rateLimiter?: RateLimiter;
	}
}
