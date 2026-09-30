/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { z } from "zod";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { defineModule } from "../modules/index.mjs";
import { createMemoryRateLimiter, DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS } from "./memory.mjs";
import type { RateLimitSpec } from "./types.mjs";

const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	windowSeconds: z.number().int().positive().max(MAX_DURATION_SECONDS),
});

/**
 * In-memory RateLimiter module: `memoryRateLimiter`'s limits and default, and
 * the budgets the prefixes' owners contribute (`rateLimitBudgetResolver`),
 * which the memory branch of `registerBuiltinRateLimiters` does not read. For
 * production multi-instance deployments, use `redisRateLimiterModule` from
 * `@o3co/auth-provider-redis`.
 */
export const memoryRateLimiterModule = defineModule({
	name: "core-rate-limiter-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"rate-limit counters fork per replica — every configured limit is effectively multiplied by the replica count, and resets on each deploy",
	},
	requires: ["config", "rateLimitBudgetResolver"] as const,
	configSchema: z.object({
		memoryRateLimiter: z
			.object({
				limits: z.record(z.string(), rateLimitSpecSchema).default({}),
				defaultLimit: rateLimitSpecSchema.default({ limit: 60, windowSeconds: 60 }),
				maxBuckets: z.coerce
					.number()
					.int()
					.positive()
					.default(DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS),
			})
			.default({
				limits: {},
				defaultLimit: { limit: 60, windowSeconds: 60 },
				maxBuckets: DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
			}),
	}),
	provides: {
		rateLimiter: (deps) => {
			const cfg = (
				deps.config as unknown as {
					memoryRateLimiter: {
						limits: Record<string, RateLimitSpec>;
						defaultLimit: RateLimitSpec;
						maxBuckets?: number;
					};
				}
			).memoryRateLimiter;
			return createMemoryRateLimiter({
				limits: cfg.limits,
				budgets: deps.rateLimitBudgetResolver,
				defaultLimit: cfg.defaultLimit,
				maxBuckets: cfg.maxBuckets,
			});
		},
	},
});
