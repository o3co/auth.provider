/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	assertUsableRateLimitSpecs,
	defineModule,
	MAX_DURATION_SECONDS,
	type RateLimiter,
	type RateLimitSpec,
	resolveSeededLimitSpecs,
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

function keyPrefix(key: string): string {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
}

interface CreateRedisRateLimiterOptions {
	client: RateLimiterClient;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
}

/**
 * Redis-backed RateLimiter. One atomic increment-and-expire per check, via
 * `RateLimiterClient.incrementWithTtlAndPttl` (or the count-only
 * `incrementWithTtl` for a client that predates it — see #458).
 *
 * It used to be `INCR` followed by a separate `EXPIRE`, issued only when the
 * count came back as 1. A process death or an `EXPIRE` error in between left
 * the key with no TTL, so its counter never reset and every later window saw a
 * count above the limit — that client was 429'd permanently, and `failMode`
 * never engaged because the check kept succeeding, it just kept answering
 * "denied" (#269).
 *
 * Consumer passes their own redis client because RateLimiter has no dispose
 * lifecycle hook — client lifetime lives in the composition root alongside
 * other redis users.
 */
export function createRedisRateLimiter(opts: CreateRedisRateLimiterOptions): RateLimiter {
	// Every spec it was given, `defaultLimit` included, must be one it can
	// apply as written — core's predicate, which the in-process limiter uses
	// too. `redisRateLimiterBuilder` accepts a config object that never passed
	// the zod schema, so this is where a zero window (`EXPIRE key 0` deletes
	// the counter), a limit of zero or less, NaN, a fraction, or a window past
	// the Date range (an `EXPIRE` Redis refuses after the `INCR`, #269's shape)
	// is refused. It used to drop such a spec and serve the default in its
	// place: a looser budget than the operator wrote. Only a default nobody
	// gave is the built-in 60 per 60 s.
	assertUsableRateLimitSpecs("createRedisRateLimiter", opts);
	const limits: Record<string, RateLimitSpec> = Object.fromEntries(
		Object.entries(opts.limits ?? {}).map(([prefix, spec]) => [
			prefix,
			{ limit: spec.limit, windowSeconds: spec.windowSeconds },
		]),
	);
	const defaultLimit: RateLimitSpec = opts.defaultLimit ?? DEFAULT_LIMIT;
	const client = opts.client;

	return {
		kind: "redis",
		async check(key) {
			const spec = limits[keyPrefix(key)] ?? defaultLimit;
			// #458: take the PTTL with the count when the client offers it, so the
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
					reason: `limit:${keyPrefix(key)}`,
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
	requires: ["rateLimiterClient", "config"] as const,
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
				// `/session/login` limits under the `login:` prefix, but its window
				// and limit are configured at `rateLimit.login`; the device
				// verification endpoint likewise under `device_verification:`,
				// configured at `oauth.deviceAuthorization.rateLimit`. Seeding
				// keeps those the single source of truth; an operator-declared
				// entry for either prefix still wins. See `resolveSeededLimitSpecs`.
				limits: resolveSeededLimitSpecs(cfg.limits, deps.config),
				defaultLimit: cfg.defaultLimit,
			});
		},
	},
});
