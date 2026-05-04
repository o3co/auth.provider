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
	readonly reason?: string;
}

export interface RateLimiterBase {
	readonly kind: string;
	/**
	 * Atomic check + increment. Key is endpoint-specific (e.g.,
	 * "login:ip:1.2.3.4", "token:client:abc").
	 */
	check(key: string, ctx: RateLimitContext): Promise<RateLimitDecision>;
}

export type RateLimiterFactory = AdapterFactory<RateLimiterBase>;

/**
 * Rate-limit spec, e.g., `{ limit: 10, windowSeconds: 60 }`. Consumed by
 * built-in adapters; custom adapters may interpret the config freely.
 */
export interface RateLimitSpec {
	readonly limit: number;
	readonly windowSeconds: number;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A2-α §6.1 — optional slot)
//
// Declared here so oauthModule can list "rateLimiter" in its `optional` array
// and the DI graph types deps.rateLimiter as RateLimiterBase | undefined.
// The slot is optional: when absent, oauth routes degrade gracefully (no
// rate-limiting applied, fail-open per createOAuthRouter semantics).
// Phase 9 Task 4 augmentation.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly rateLimiter?: RateLimiterBase;
	}
}

// ---------------------------------------------------------------------------
// Backing client interface (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

// RateLimiterClient backing-client interface relocated to
// @o3co/auth-provider-redis (v0.5.0 pre-tag interface review S3).
