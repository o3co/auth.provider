/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	createRateLimitBudgetLookup,
	defineModule,
	MAX_DURATION_SECONDS,
	type RateLimitBudgetResolver,
	type RateLimiter,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RateLimiterClient } from "./clients.mjs";

interface RedisRateLimiterConfig {
	type?: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	client?: RateLimiterClient;
}

/** The built-in default, for a configuration that gives none. */
const DEFAULT_LIMIT: RateLimitSpec = { limit: 60, windowSeconds: 60 };

interface CreateRedisRateLimiterOptions {
	client: RateLimiterClient;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	/**
	 * The budgets the prefixes' owners contributed, read at each check; an
	 * entry of `limits` wins over one (core's `createRateLimitBudgetLookup`).
	 */
	budgets?: RateLimitBudgetResolver;
}

/**
 * Redis-backed RateLimiter. One atomic increment-and-expire per check, via
 * `RateLimiterClient.incrementWithTtlAndPttl` (or the count-only
 * `incrementWithTtl` of a client without it). A separate `EXPIRE` after `INCR`
 * could leave the key with no TTL if the process died or the `EXPIRE` failed
 * in between: the counter would never reset, that client would be refused for
 * good, and `failMode` would never engage, since the check still succeeds.
 *
 * The consumer passes the Redis client because RateLimiter has no dispose
 * hook; its lifetime belongs to the composition root.
 */
export function createRedisRateLimiter(opts: CreateRedisRateLimiterOptions): RateLimiter {
	// Every spec it was given, `defaultLimit` included, must be one it can
	// apply as written: core's lookup refuses anything else, by the predicate
	// the in-process limiter is held to, and holds what it checked, so a later
	// change to the caller's objects cannot hand Redis a window nobody
	// validated. `redisRateLimiterBuilder` accepts a config object that never
	// passed the zod schema, so this is where a zero window (`EXPIRE key 0`
	// deletes the counter), a limit of zero or less, NaN, a fraction, or a
	// window past the Date range (an `EXPIRE` Redis refuses after the `INCR`)
	// is refused, rather than replaced by the default, a looser budget than
	// the operator wrote. Only a default nobody gave is the built-in 60 per
	// 60 s.
	const budgetFor = createRateLimitBudgetLookup("createRedisRateLimiter", {
		...(opts.limits === undefined ? {} : { limits: opts.limits }),
		// Only `undefined` is "not given": a `null` default is refused.
		defaultLimit: opts.defaultLimit === undefined ? DEFAULT_LIMIT : opts.defaultLimit,
		...(opts.budgets === undefined ? {} : { budgets: opts.budgets }),
	});
	const client = opts.client;

	return {
		kind: "redis",
		async check(key) {
			const { prefix, spec } = budgetFor(key);
			// Take the PTTL with the count when the client offers it, so the
			// decision can say when the window ends — without `resetAt` the guard's
			// 429 carries no `Retry-After` behind Redis while the memory adapter's
			// does. A client on the one-method contract still works, minus that.
			const { count, pttl } = client.incrementWithTtlAndPttl
				? await client.incrementWithTtlAndPttl(key, spec.windowSeconds)
				: { count: await client.incrementWithTtl(key, spec.windowSeconds), pttl: undefined };
			// -1 / -2 cannot follow a script that just guaranteed the expiry; a
			// client answering them broke the contract, and no reset time beats a
			// wrong one.
			const resetAt =
				pttl !== undefined && pttl > 0 ? { resetAt: new Date(Date.now() + pttl) } : {};
			if (count > spec.limit) {
				return {
					allowed: false,
					remaining: 0,
					reason: `limit:${prefix}`,
					limit: spec.limit,
					...resetAt,
				};
			}
			return {
				allowed: true,
				remaining: spec.limit - count,
				limit: spec.limit,
				...resetAt,
			};
		},
	};
}

/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisRateLimiterBuilder);
 */
export const redisRateLimiterBuilder: AdapterBuilder<RateLimiter> = (config, _ctx) => {
	const cfg = config as unknown as RedisRateLimiterConfig;
	if (!cfg.client) {
		throw new Error(
			'Rate limiter "redis" requires config.client; the built-in limiter does not create its own redis client because RateLimiter has no disposal hook.',
		);
	}
	return createRedisRateLimiter({
		client: cfg.client as RateLimiterClient,
		limits: cfg.limits,
		defaultLimit: cfg.defaultLimit,
	});
};

const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	// One year at most, as core's schema holds every duration an operator writes.
	windowSeconds: z.number().int().positive().max(MAX_DURATION_SECONDS),
});

/**
 * `defineModule` manifest for the redis RateLimiter. Reads `redisRateLimiter`
 * config slice (limits + defaultLimit). The redis client itself comes from
 * the `rateLimiterClient` ComponentMap slot (per-purpose interface declared
 * in `@o3co/auth-provider-core`'s `ratelimit/types.mts`).
 */
export const redisRateLimiterModule = defineModule({
	name: "redis-rate-limiter",
	requires: ["rateLimiterClient", "config", "rateLimitBudgetResolver"] as const,
	configSchema: z.object({
		redisRateLimiter: z
			.object({
				limits: z.record(z.string(), rateLimitSpecSchema).default({}),
				defaultLimit: rateLimitSpecSchema.default({ limit: 60, windowSeconds: 60 }),
			})
			.default({ limits: {}, defaultLimit: { limit: 60, windowSeconds: 60 } }),
	}),
	provides: {
		rateLimiter: (deps) => {
			const cfg = (
				deps.config as unknown as {
					redisRateLimiter: {
						limits: Record<string, RateLimitSpec>;
						defaultLimit: RateLimitSpec;
					};
				}
			).redisRateLimiter;
			return createRedisRateLimiter({
				client: deps.rateLimiterClient,
				// What an operator declared on this limiter wins over the budget a
				// prefix's owner contributed, which wins over `defaultLimit`.
				limits: cfg.limits,
				budgets: deps.rateLimitBudgetResolver,
				defaultLimit: cfg.defaultLimit,
			});
		},
	},
});
