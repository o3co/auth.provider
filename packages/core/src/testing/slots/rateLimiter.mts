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
 * The test double of the `RateLimiter` port, the `rateLimiter` slot's
 * value. `createTestRateLimiter` records every key checked, allows every
 * check or counts each key against a limit, and can stand in for a backend
 * that is down. The port's contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import type { RateLimitDecision, RateLimiter, RateLimitFailMode } from "../../ratelimit/types.mjs";

export interface TestRateLimiterOptions {
	/** The limiter's outage policy. Absent, it declares none. */
	readonly failMode?: RateLimitFailMode;
	/** How many checks each key is allowed; absent, every check is. Never reset. */
	readonly limit?: number;
}

/** A `RateLimiter` for tests. */
export interface TestRateLimiter extends RateLimiter {
	readonly kind: "test";
	/** Every key checked, oldest first. */
	readonly checked: readonly string[];
	/** From now on every check rejects with `error` and counts nothing: a backend that is down. */
	failWith(error: unknown): void;
	/** Answer again. */
	recover(): void;
}

export function createTestRateLimiter(options: TestRateLimiterOptions = {}): TestRateLimiter {
	let checked: readonly string[] = Object.freeze([]);
	let failure: { readonly error: unknown } | undefined;
	const counts = new Map<string, number>();
	const { limit } = options;
	return {
		kind: "test",
		...(options.failMode === undefined ? {} : { failMode: options.failMode }),
		get checked() {
			return checked;
		},
		failWith(error: unknown): void {
			failure = { error };
		},
		recover(): void {
			failure = undefined;
		},
		async check(key: string): Promise<RateLimitDecision> {
			if (failure !== undefined) throw failure.error;
			checked = Object.freeze([...checked, key]);
			if (limit === undefined) return { allowed: true };
			const count = (counts.get(key) ?? 0) + 1;
			counts.set(key, count);
			return { allowed: count <= limit, remaining: Math.max(limit - count, 0), limit };
		},
	};
}
