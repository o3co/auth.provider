/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	defineModule,
	type RateLimiterBase,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import { z } from "zod";

interface RedisRateLimiterConfig {
	type?: string;
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
	client?: {
		incr(key: string): Promise<number>;
		expire(key: string, seconds: number): Promise<number>;
	};
}

function normalizeLimits(raw: unknown): Record<string, RateLimitSpec> {
	if (raw == null || typeof raw !== "object") return {};
	const result: Record<string, RateLimitSpec> = {};
	for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
		if (v && typeof v === "object" && "limit" in v && "windowSeconds" in v) {
			const spec = v as { limit: unknown; windowSeconds: unknown };
			if (typeof spec.limit === "number" && typeof spec.windowSeconds === "number") {
				result[k] = { limit: spec.limit, windowSeconds: spec.windowSeconds };
			}
		}
	}
	return result;
}

function keyPrefix(key: string): string {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
}

interface CreateRedisRateLimiterOptions {
	client: {
		incr(key: string): Promise<number>;
		expire(key: string, seconds: number): Promise<number>;
	};
	limits?: Record<string, RateLimitSpec>;
	defaultLimit?: RateLimitSpec;
}

/**
 * Redis-backed RateLimiter. Atomic INCR with TTL set on first hit. Consumer
 * passes their own redis client because RateLimiterBase has no dispose
 * lifecycle hook — client lifetime lives in the composition root alongside
 * other redis users.
 */
export function createRedisRateLimiter(opts: CreateRedisRateLimiterOptions): RateLimiterBase {
	const limits = normalizeLimits(opts.limits);
	const defaultLimit: RateLimitSpec = opts.defaultLimit ?? { limit: 60, windowSeconds: 60 };
	const client = opts.client;

	return {
		kind: "redis",
		async check(key) {
			const spec = limits[keyPrefix(key)] ?? defaultLimit;
			const count = await client.incr(key);
			if (count === 1) {
				await client.expire(key, spec.windowSeconds);
			}
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
export const redisRateLimiterBuilder: AdapterBuilder<RateLimiterBase> = (config, _ctx) => {
	const cfg = config as unknown as RedisRateLimiterConfig;
	if (!cfg.client) {
		throw new Error(
			'Rate limiter "redis" requires config.client; the built-in limiter does not create its own redis client because RateLimiterBase has no disposal hook.',
		);
	}
	return createRedisRateLimiter({
		client: cfg.client,
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
 * the `redisClient` ComponentMap slot.
 */
export const redisRateLimiterModule = defineModule({
	name: "redis-rate-limiter",
	requires: ["redisClient", "config"] as const,
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
			// The redisClient ComponentMap shape is the structural client
			// with all redis ops. RateLimiter only needs incr + expire,
			// so we pass through and trust the structural compat.
			return createRedisRateLimiter({
				client: deps.redisClient as unknown as {
					incr(key: string): Promise<number>;
					expire(key: string, seconds: number): Promise<number>;
				},
				limits: cfg.limits,
				defaultLimit: cfg.defaultLimit,
			});
		},
	},
});
