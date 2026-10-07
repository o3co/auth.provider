/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { z } from "zod";
import { wholeNumberInRangeFromEnv } from "../config/application.schema.mjs";
import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { coreReference } from "../config/references.mjs";
import { defineModule } from "../modules/index.mjs";
import { createMemoryRateLimiter } from "./memory.mjs";
import { refuseVerifierLimitEntries } from "./verifierLimits.mjs";

/** A budget as the section writes it; each number read from the string a variable carries. */
const rateLimitSpecSchema = z
	.object({
		limit: wholeNumberInRangeFromEnv(1),
		windowSeconds: wholeNumberInRangeFromEnv(1, MAX_DURATION_SECONDS),
	})
	.strict();

/**
 * The schema of `core-rate-limiter-memory {}`, the module's own section:
 * per-prefix `limits`, none naming a verifier's prefix, the `defaultLimit` a
 * key nothing covers falls to, and `maxBuckets`, the bound on the counters it
 * holds. Strict at every level. It fills no default: core's
 * `config/reference.conf` ships every value.
 */
export const memoryRateLimiterSectionSchema = z
	.object({
		limits: z.record(z.string(), rateLimitSpecSchema).superRefine(refuseVerifierLimitEntries),
		defaultLimit: rateLimitSpecSchema,
		maxBuckets: wholeNumberInRangeFromEnv(1),
	})
	.strict();

/**
 * In-memory RateLimiter module: a key's budget is its own section's `limits`
 * entry for the key's prefix, else its `defaultLimit`, with `maxBuckets`
 * bounding the counters it holds. `memoryRateLimiter`, the
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
	provides: {
		rateLimiter: ({ section }) =>
			createMemoryRateLimiter({
				limits: section.limits,
				defaultLimit: section.defaultLimit,
				maxBuckets: section.maxBuckets,
			}),
	},
});
