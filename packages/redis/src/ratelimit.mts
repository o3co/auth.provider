/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	defineModule,
	type RateLimiter,
	type RateLimitSpec,
	resolveLoginLimitSpec,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RateLimiterClient } from "./clients.mjs";

interface RedisRateLimiterConfig {
	type?: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	client?: RateLimiterClient;
}

/**
 * Whether a value is usable as a `limit` or `windowSeconds`.
 *
 * Both must be positive integers, and the check lives here rather than only in
 * `rateLimitSpecSchema` because `redisRateLimiterBuilder` accepts a config
 * object that never passed the schema. A `windowSeconds` of 0 would reach
 * `EXPIRE key 0`, which *deletes* the key — every request would then see a
 * count of 1 and the limiter would silently never limit anything. A
 * non-positive `limit` denies every request instead. Neither can be what the
 * operator meant, so a spec carrying one is dropped and the caller falls back
 * to `defaultLimit`.
 */
const isPositiveInteger = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value > 0;

/** Whether an arbitrary value is a usable {@link RateLimitSpec}. */
const isRateLimitSpec = (value: unknown): value is RateLimitSpec =>
	typeof value === "object" &&
	value !== null &&
	isPositiveInteger((value as { limit?: unknown }).limit) &&
	isPositiveInteger((value as { windowSeconds?: unknown }).windowSeconds);

function normalizeLimits(raw: unknown): Record<string, RateLimitSpec> {
	if (raw == null || typeof raw !== "object") return {};
	const result: Record<string, RateLimitSpec> = {};
	for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
		if (isRateLimitSpec(v)) {
			result[k] = { limit: v.limit, windowSeconds: v.windowSeconds };
		}
	}
	return result;
}

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
 * `RateLimiterClient.incrementWithTtl`.
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
	const limits = normalizeLimits(opts.limits);
	// `defaultLimit` gets the same screening as the per-prefix specs: it is the
	// fallback every unmatched key lands on, so a bad one is worse, not better.
	//
	// Screened as an unknown, not as a `RateLimitSpec`: `redisRateLimiterBuilder`
	// accepts a config object that never passed the zod schema, so this can
	// arrive as `null` or as a non-object. Reading `.limit` off it first would
	// throw at construction — in the one component whose job is to keep working
	// while other things go wrong.
	const providedDefault = opts.defaultLimit as unknown;
	const defaultLimit: RateLimitSpec = isRateLimitSpec(providedDefault)
		? providedDefault
		: { limit: 60, windowSeconds: 60 };
	const client = opts.client;

	return {
		kind: "redis",
		async check(key) {
			const spec = limits[keyPrefix(key)] ?? defaultLimit;
			const count = await client.incrementWithTtl(key, spec.windowSeconds);
			if (count > spec.limit) {
				return {
					allowed: false,
					remaining: 0,
					reason: `limit:${keyPrefix(key)}`,
				};
			}
			return {
				allowed: true,
				remaining: spec.limit - count,
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
	windowSeconds: z.number().int().positive(),
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
				// and limit are configured at `rateLimit.login`. Seeding keeps that
				// the single source of truth; an operator-declared `limits.login`
				// still wins. See `resolveLoginLimitSpec` (#270).
				limits: resolveLoginLimitSpec(cfg.limits, deps.config),
				defaultLimit: cfg.defaultLimit,
			});
		},
	},
});
