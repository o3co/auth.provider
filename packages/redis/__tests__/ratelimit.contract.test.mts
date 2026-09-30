/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The Redis rate limiter against the `RateLimiter` port's contract suite,
 * published on core's testing entry: over a stand-in for the atomic
 * `incrementWithTtl` script, one that answers and one whose connection is
 * down, each under both outage policies the limiter can answer.
 */

import { rateLimiterContract } from "@o3co/auth-provider-core/testing";
import { describe, it } from "vitest";
import { createRedisRateLimiter } from "../src/ratelimit.mjs";

/** A Redis stand-in counting per key, as the script does within one window. */
const answering = () => {
	const counts = new Map<string, number>();
	return {
		async incrementWithTtl(key: string, _ttlSeconds: number) {
			const next = (counts.get(key) ?? 0) + 1;
			counts.set(key, next);
			return next;
		},
	};
};

const down = () => ({
	async incrementWithTtl(): Promise<number> {
		throw new Error("connect ECONNREFUSED 127.0.0.1:6379");
	},
});

describe.each(["open", "closed"] as const)(
	"createRedisRateLimiter under failMode %s — the RateLimiter contract",
	(failMode) => {
		it.each(
			rateLimiterContract({
				build: () => createRedisRateLimiter({ client: answering(), failMode }),
				withOutage: () => createRedisRateLimiter({ client: down(), failMode }),
				withBudget: (spec) =>
					createRedisRateLimiter({ client: answering(), defaultLimit: spec, failMode }),
			}),
		)("$name", async ({ run }) => {
			await run();
		});
	},
);
