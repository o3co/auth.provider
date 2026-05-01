/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { z } from "zod";
import { defineModule } from "../modules/index.mjs";
import type { RateLimiterBase, RateLimitSpec } from "./types.mjs";

interface BucketState {
	count: number;
	resetAt: number;
}

const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	windowSeconds: z.number().int().positive(),
});

function keyPrefix(key: string): string {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
}

function createMemoryRateLimiter(
	limits: Record<string, RateLimitSpec>,
	defaultLimit: RateLimitSpec,
): RateLimiterBase {
	const buckets = new Map<string, BucketState>();
	return {
		kind: "memory",
		async check(key) {
			const now = Date.now();
			const spec = limits[keyPrefix(key)] ?? defaultLimit;
			const bucket = buckets.get(key);
			if (!bucket || bucket.resetAt <= now) {
				const fresh: BucketState = {
					count: 1,
					resetAt: now + spec.windowSeconds * 1000,
				};
				buckets.set(key, fresh);
				return {
					allowed: true,
					remaining: spec.limit - 1,
					resetAt: new Date(fresh.resetAt),
				};
			}
			if (bucket.count >= spec.limit) {
				return {
					allowed: false,
					remaining: 0,
					resetAt: new Date(bucket.resetAt),
					reason: `limit:${keyPrefix(key)}`,
				};
			}
			bucket.count += 1;
			return {
				allowed: true,
				remaining: spec.limit - bucket.count,
				resetAt: new Date(bucket.resetAt),
			};
		},
	};
}

/**
 * In-memory RateLimiter module. Matches the existing memory branch of
 * `registerBuiltinRateLimiters`. For production multi-instance deployments,
 * use `redisRateLimiterModule` from `@o3co/auth-provider-redis`.
 *
 * Phase 10 Q3: Module-pattern parity for the `rateLimiter` ComponentMap slot.
 */
export const memoryRateLimiterModule = defineModule({
	name: "core-rate-limiter-memory",
	requires: ["config"] as const,
	configSchema: z.object({
		memoryRateLimiter: z
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
					memoryRateLimiter: {
						limits: Record<string, RateLimitSpec>;
						defaultLimit: RateLimitSpec;
					};
				}
			).memoryRateLimiter;
			return createMemoryRateLimiter(cfg.limits, cfg.defaultLimit);
		},
	},
});
