/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	createRateLimitBudgetLookup,
	defineModule,
	MAX_DURATION_SECONDS,
	type RateLimiter,
	type RateLimitFailMode,
	type RateLimitSpec,
	refuseVerifierLimitEntries,
	shownConfigValue,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RateLimiterClient } from "./clients.mjs";
import { redisReference } from "./internal/section.mjs";

interface RedisRateLimiterConfig {
	type?: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	client?: RateLimiterClient;
	failMode?: RateLimitFailMode;
}

/** The built-in default, for a configuration that gives none. */
const DEFAULT_LIMIT: RateLimitSpec = { limit: 60, windowSeconds: 60 };

interface CreateRedisRateLimiterOptions {
	client: RateLimiterClient;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	/** The limiter's outage policy (`RateLimiter.failMode`); not given, none (closed). */
	failMode?: RateLimitFailMode;
}

/** `failMode` as given, or a `RangeError` naming it when it is neither policy. */
function checkedFailMode(
	who: string,
	name: string,
	failMode: unknown,
): RateLimitFailMode | undefined {
	if (failMode === undefined || failMode === "open" || failMode === "closed") return failMode;
	throw new RangeError(
		`${who}${name} must be "open" or "closed" (got ${shownConfigValue(failMode)})`,
	);
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
	// Every spec given, `defaultLimit` included, is refused unless usable as
	// written (a zero window deletes the counter; one past the Date range is an
	// `EXPIRE` Redis refuses), never replaced by the default. Only a default
	// nobody gave is the built-in 60 per 60 s.
	const budgetFor = createRateLimitBudgetLookup("createRedisRateLimiter", {
		...(opts.limits === undefined ? {} : { limits: opts.limits }),
		// Only `undefined` is "not given": a `null` default is refused.
		defaultLimit: opts.defaultLimit === undefined ? DEFAULT_LIMIT : opts.defaultLimit,
	});
	const client = opts.client;
	const failMode = checkedFailMode("createRedisRateLimiter: ", "failMode", opts.failMode);

	return {
		kind: "redis",
		defaultLimit: budgetFor.defaultLimit,
		...(failMode === undefined ? {} : { failMode }),
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
 * AdapterFactory builder, over `client`, `limits`, `defaultLimit` and
 * `failMode` from its config, as `redisRateLimiterModule` builds it from its
 * section. Consumer wires:
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
		failMode: cfg.failMode,
	});
};

/** A budget as the section writes it; each number read from the string a variable carries. */
const rateLimitSpecSchema = z
	.object({
		limit: wholeNumberInRangeFromEnv(1),
		// One year at most, as core holds every duration an operator writes.
		windowSeconds: wholeNumberInRangeFromEnv(1, MAX_DURATION_SECONDS),
	})
	.strict();

/**
 * The schema of `redis-rate-limiter {}`, the module's own section: per-prefix
 * `limits`, none naming a verifier's prefix, the `defaultLimit` a key nothing
 * covers falls to, and `failMode`, the limiter's outage policy. Strict at
 * every level.
 */
export const redisRateLimiterSectionSchema = z
	.object({
		limits: z
			.record(z.string(), rateLimitSpecSchema)
			.superRefine(refuseVerifierLimitEntries)
			.default({}),
		defaultLimit: rateLimitSpecSchema.default(() => ({ ...DEFAULT_LIMIT })),
		failMode: z.enum(["open", "closed"]).default("closed"),
	})
	.strict()
	.default(() => ({ limits: {}, defaultLimit: { ...DEFAULT_LIMIT }, failMode: "closed" as const }));

/**
 * `defineModule` manifest for the redis RateLimiter. Reads its own section,
 * `redis-rate-limiter` (limits, defaultLimit, and `failMode`, the limiter's
 * outage policy).
 * `redisRateLimiter` and `rateLimit.failMode`, the paths its keys moved from,
 * and `RATE_LIMIT_FAIL_MODE`, its variable's old name, refuse boot naming the
 * new ones. The redis client itself comes from the `rateLimiterClient`
 * ComponentMap slot (per-purpose interface declared in
 * `@o3co/auth-provider-core`'s `ratelimit/types.mts`).
 */
export const redisRateLimiterModule = defineModule({
	name: "redis-rate-limiter",
	section: {
		schema: redisRateLimiterSectionSchema,
		reference: redisReference(),
		relocatedFrom: {
			redisRateLimiter: { to: "", environmentVariable: null },
			"rateLimit.failMode": "failMode",
		},
		renamedVariables: { RATE_LIMIT_FAIL_MODE: "rateLimit.failMode" },
	},
	requires: ["rateLimiterClient"] as const,
	provides: {
		rateLimiter: ({ section, rateLimiterClient }) =>
			createRedisRateLimiter({
				failMode: section.failMode,
				client: rateLimiterClient,
				limits: section.limits,
				defaultLimit: section.defaultLimit,
			}),
	},
});
