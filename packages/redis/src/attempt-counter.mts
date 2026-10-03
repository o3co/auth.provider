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
 * Redis-backed `AttemptCounter`: one atomic script per attempt
 * (`AttemptCounterClient.consume`), a hash per key under `<keyPrefix><key>`
 * holding the window's count and end.
 *
 * Its own key namespace: its keys share the `<tag>:<id>` form of the rate
 * limiter's, which keys them bare, and a shared server must never count an
 * attempt in a limiter's counter or the reverse.
 *
 * Two clocks. A window's end and whether one is running are judged on this
 * side's clock (`now`), the one the attempt guard reads the count on. The key
 * expires on the server's (`PEXPIREAT`), `ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS`
 * past the window's end, so a server running ahead by up to that never frees
 * a running window. Redis frees ended windows; nothing deletes one.
 *
 * A reply that is no count under the spec (`readAttemptCount`) rejects, as an
 * unreachable server does: the guard answers either as an outage.
 */

import {
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	defineModule,
	isAttemptKey,
	isAttemptSpec,
	readAttemptCount,
} from "@o3co/auth-provider-core";
import type { AttemptCounterClient, AttemptCounterConsumeReply } from "./clients.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/** The key namespace a counter given none keys its windows under. */
export const DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX = "attempt:";

export interface RedisAttemptCounterOptions {
	readonly client: AttemptCounterClient;
	/** Default {@link DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX}. */
	readonly keyPrefix?: string;
	/** Epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
}

const isConsumeReply = (reply: unknown): reply is AttemptCounterConsumeReply => {
	if (typeof reply !== "object" || reply === null) return false;
	const { allowed, count, resetAtMs } = reply as Record<string, unknown>;
	return (
		typeof allowed === "boolean" &&
		typeof count === "number" &&
		Number.isSafeInteger(count) &&
		count >= 1 &&
		typeof resetAtMs === "number"
	);
};

export function createRedisAttemptCounter(options: RedisAttemptCounterOptions): AttemptCounter {
	const { client } = options;
	const keyPrefix = options.keyPrefix ?? DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX;
	const now = options.now ?? Date.now;

	return {
		async consume(key: string, spec: AttemptSpec): Promise<AttemptCount> {
			if (!isAttemptKey(key)) {
				throw new TypeError(
					"createRedisAttemptCounter: key must be a non-empty string of at most 512 characters",
				);
			}
			if (!isAttemptSpec(spec)) {
				throw new RangeError(
					"createRedisAttemptCounter: spec must be { limit, windowSeconds } as positive whole numbers, the window at most a day",
				);
			}
			const { limit, windowSeconds } = spec;
			const nowMs = Math.floor(now());
			if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
				throw new RangeError("createRedisAttemptCounter: the clock answered no instant");
			}
			const resetAtMs = nowMs + windowSeconds * 1000;
			const reply: unknown = await client.consume(`${keyPrefix}${key}`, {
				nowMs,
				limit,
				resetAtMs,
				expiresAtMs: resetAtMs + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
			});
			// A refused attempt is one at or past the limit; any other reply is no count.
			const count =
				isConsumeReply(reply) && (reply.allowed || reply.count >= limit)
					? readAttemptCount(
							{
								allowed: reply.allowed,
								remaining: reply.allowed ? limit - reply.count : 0,
								resetAt: new Date(reply.resetAtMs),
							},
							spec,
							nowMs,
						)
					: undefined;
			if (count === undefined) {
				throw new Error("createRedisAttemptCounter: the attempt counter answered no count");
			}
			return count;
		},
	};
}

/**
 * `defineModule` manifest for the Redis `AttemptCounter`, filling the
 * `attemptCounter` slot. Its section, `redis-attempt-counter`, holds
 * `keyPrefix` (strict); the client comes from the `attemptCounterClient` slot.
 */
export const redisAttemptCounterModule = defineModule({
	name: "redis-attempt-counter",
	requires: ["attemptCounterClient"] as const,
	section: {
		schema: keyPrefixSection(DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX),
		reference: redisReference(),
	},
	provides: {
		attemptCounter: ({ section, attemptCounterClient }) =>
			createRedisAttemptCounter({ client: attemptCounterClient, keyPrefix: section.keyPrefix }),
	},
});
