/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { z } from "zod";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { coreReference } from "../config/references.mjs";
import { defineModule } from "../modules/index.mjs";
import { createMemoryRateLimiter, DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS } from "./memory.mjs";

/** A budget as the section writes it; each number read from the string a variable carries. */
const rateLimitSpecSchema = z
	.object({
		limit: z.coerce.number().int().positive(),
		windowSeconds: z.coerce.number().int().positive().max(MAX_DURATION_SECONDS),
	})
	.strict();

/**
 * The schema of `core-rate-limiter-memory {}`, the module's own section:
 * per-prefix `limits`, the `defaultLimit` a key nothing covers falls to, and
 * `maxBuckets`, the bound on the counters it holds. Strict at every level.
 */
export const memoryRateLimiterSectionSchema = z
	.object({
		limits: z.record(z.string(), rateLimitSpecSchema).default({}),
		defaultLimit: rateLimitSpecSchema.default({ limit: 60, windowSeconds: 60 }),
		maxBuckets: z.coerce.number().int().positive().default(DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS),
	})
	.strict()
	.default(() => ({
		limits: {},
		defaultLimit: { limit: 60, windowSeconds: 60 },
		maxBuckets: DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
	}));

/**
 * In-memory RateLimiter module: its own section's limits, default and bucket
 * bound, and the budgets the prefixes' owners contribute
 * (`rateLimitBudgetResolver`), which the memory branch of
 * `registerBuiltinRateLimiters` does not read. `memoryRateLimiter`, the
 * section's old path, and `MEMORY_RATE_LIMITER_MAX_BUCKETS`, its variable's
 * old name, refuse boot naming the new ones. For production multi-instance
 * deployments, use `redisRateLimiterModule` from `@o3co/auth-provider-redis`.
 */
export const memoryRateLimiterModule = defineModule({
	name: "core-rate-limiter-memory",
	// Core's own `reference.conf` holds the defaults, binds
	// CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS and captures the renamed variable.
	section: {
		schema: memoryRateLimiterSectionSchema,
		reference: coreReference(),
		relocatedFrom: {
			memoryRateLimiter: { to: "", environmentVariable: null },
			"memoryRateLimiter.maxBuckets": "maxBuckets",
		},
		renamedVariables: { MEMORY_RATE_LIMITER_MAX_BUCKETS: "memoryRateLimiter.maxBuckets" },
	},
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"rate-limit counters fork per replica — every configured limit is effectively multiplied by the replica count, and resets on each deploy",
	},
	requires: ["rateLimitBudgetResolver"] as const,
	provides: {
		rateLimiter: ({ section, rateLimitBudgetResolver }) =>
			createMemoryRateLimiter({
				limits: section.limits,
				budgets: rateLimitBudgetResolver,
				defaultLimit: section.defaultLimit,
				maxBuckets: section.maxBuckets,
			}),
	},
});
