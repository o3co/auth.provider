/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { z } from "zod";
import { defineModule } from "../modules/index.mjs";
import { createMemoryRateLimiter, DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS } from "./memory.mjs";
import type { RateLimitSpec } from "./types.mjs";

const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	windowSeconds: z.number().int().positive(),
});

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
				defaultLimit: cfg.defaultLimit,
				maxBuckets: cfg.maxBuckets,
			});
		},
	},
});
