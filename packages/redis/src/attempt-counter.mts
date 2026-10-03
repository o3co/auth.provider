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
 * The module refuses a server whose `maxmemory-policy` is not `noeviction`:
 * every window's key carries a TTL, so any evicting policy may drop a running
 * window, and its key would start a fresh one, loosening a verifier's limit.
 */

import {
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	consoleLogger,
	defineModule,
	isAttemptKey,
	isAttemptSpec,
	isStorableExpiry,
	type Logger,
	loggableError,
	readAttemptCount,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type {
	AttemptCounterClient,
	AttemptCounterConsumeReply,
	RedisDurability,
} from "./clients.mjs";
import {
	ALLKEYS_POLICIES,
	RedisStoreEvictableError,
	VOLATILE_POLICIES,
} from "./internal/eviction-policy.mjs";
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

export function createRedisAttemptCounter(options: RedisAttemptCounterOptions): AttemptCounter {
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

/** What a policy that is not `noeviction` may evict, for the refusal's message. */
const evictedBy = (policy: string): string =>
	ALLKEYS_POLICIES.has(policy)
		? "any key"
		: VOLATILE_POLICIES.has(policy)
			? "any key with a TTL"
			: "keys under memory pressure";

/**
 * The module's boot check, on what `durability` answers: a policy read and not
 * `noeviction` throws a `RedisStoreEvictableError` (`attempt-counter-evictable`);
 * a policy that could not be read is one warning that the check could not run,
 * and the boot goes on. A server that cannot answer at all fails the boot.
 */
async function checkAttemptCounterEviction(
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	const report = await durability();
	const policy = report.maxmemoryPolicy;
	if (policy === undefined) {
		logger.warn(
			{
				store: "attemptCounter",
				adapter: "redis",
				unread: ["maxmemory-policy"],
				...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
			},
			"attempt_counter_durability_unchecked",
		);
		return;
	}
	if (policy !== "noeviction") {
		throw new RedisStoreEvictableError("attemptCounter", policy, {
			reason: "attempt-counter-evictable",
			evicts: evictedBy(policy),
			holds:
				"running attempt windows, every one keyed with a TTL, and a key whose window is evicted starts a fresh one, loosening a verifier's limit",
			remedy: '"noeviction"',
		});
	}
}

/**
 * `defineModule` manifest for the Redis `AttemptCounter`, filling the
 * `attemptCounter` slot. Its section, `redis-attempt-counter`, holds
 * `keyPrefix` (strict); the client comes from the `attemptCounterClient` slot.
 * Before it provides the counter it runs the eviction check above, writing its
 * warning on the `logger` slot, or on `consoleLogger`.
 */
export const redisAttemptCounterModule = defineModule({
	name: "redis-attempt-counter",
	requires: ["attemptCounterClient"] as const,
	optional: ["logger"] as const,
	section: {
		schema: sectionSchema,
		reference: redisReference(),
	},
	provides: {
		attemptCounter: async ({ section, attemptCounterClient, logger }) => {
			const counter = createRedisAttemptCounter({
				client: attemptCounterClient,
				keyPrefix: section.keyPrefix,
			});
			await checkAttemptCounterEviction(
				() => attemptCounterClient.durability(),
				logger ?? consoleLogger,
			);
			return counter;
		},
	},
});
