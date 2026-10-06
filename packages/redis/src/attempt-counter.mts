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
 * Clocks. A window's end is set on this side's clock (`now`), the one the
 * attempt guard reads the count on, and its key's TTL is relative: the
 * window's length plus `ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS`. A window is running
 * while its end is after `now` or its TTL is above the allowance, so neither a
 * server's clock set apart nor a replica's running ahead ends one early. A
 * replica ahead past the window's end is answered that end, which the guard
 * takes within the allowance and answers `503` beyond it. A forward step of
 * the server's wall clock still expires windows early, as for every TTL.
 *
 * A reply that is no count under the spec (`readAttemptCount`) rejects, as an
 * unreachable server does: the guard answers either as an outage.
 *
 * The factory refuses a server whose `maxmemory-policy` is not `noeviction`
 * (`internal/eviction-policy.mts`): every window's key carries a TTL, so any
 * evicting policy may drop a running window, and its key would start a fresh
 * one, loosening a verifier's limit.
 */

import {
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	defineModule,
	isAttemptKey,
	isAttemptSpec,
	isStorableExpiry,
	readAttemptCount,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { AttemptCounterClient, AttemptCounterConsumeReply } from "./clients.mjs";
import { requireNoEviction } from "./internal/eviction-policy.mjs";
import { redisReference } from "./internal/section.mjs";

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

/**
 * The Redis {@link AttemptCounter}. It resolves once the server's eviction
 * policy passes the gate (`internal/eviction-policy.mts`); an option it
 * cannot use rejects before the server is asked.
 */
export async function createRedisAttemptCounter(
	options: RedisAttemptCounterOptions,
): Promise<AttemptCounter> {
	const counter = buildRedisAttemptCounter(options);
	await requireNoEviction("attemptCounter", () => options.client.durability(), {
		reason: "attempt-counter-evictable",
		holds:
			"running attempt windows, every one keyed with a TTL, and a key whose window is evicted starts a fresh one, loosening a verifier's limit",
	});
	return counter;
}

function buildRedisAttemptCounter(options: RedisAttemptCounterOptions): AttemptCounter {
	const { client } = options;
	const keyPrefix = options.keyPrefix ?? DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX;
	if (keyPrefix === "") {
		throw new RangeError(
			"createRedisAttemptCounter: keyPrefix must not be empty: the rate limiter keys the same form under no prefix",
		);
	}
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
			const resetAtMs = nowMs + windowSeconds * 1000;
			// A window it may open must end, with its key, within the Date range.
			if (
				!Number.isSafeInteger(nowMs) ||
				nowMs < 0 ||
				!isStorableExpiry(resetAtMs + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS)
			) {
				throw new RangeError("createRedisAttemptCounter: the clock answered no instant");
			}
			const reply: unknown = await client.consume(`${keyPrefix}${key}`, {
				nowMs,
				limit,
				resetAtMs,
				expiryAllowanceMs: ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
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

/** The module's section: its key namespace alone, strict, never empty. */
const sectionSchema = z
	.object({ keyPrefix: z.string().min(1).default(DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX) })
	.strict()
	.default(() => ({ keyPrefix: DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX }));

/**
 * `defineModule` manifest for the Redis `AttemptCounter`, filling the
 * `attemptCounter` slot. Its section, `redis-attempt-counter`, holds
 * `keyPrefix` (strict); the client comes from the `attemptCounterClient` slot.
 * The counter is built by {@link createRedisAttemptCounter}, so a server that
 * fails the eviction gate refuses the boot.
 */
export const redisAttemptCounterModule = defineModule({
	name: "redis-attempt-counter",
	requires: ["attemptCounterClient"] as const,
	section: {
		schema: sectionSchema,
		reference: redisReference(),
	},
	provides: {
		attemptCounter: ({ section, attemptCounterClient }) =>
			createRedisAttemptCounter({ client: attemptCounterClient, keyPrefix: section.keyPrefix }),
	},
});
