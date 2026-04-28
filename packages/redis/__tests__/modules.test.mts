/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { redisChallengeStoreModule, redisReplaySeenSetModule } from "../src/index.mjs";

describe("redisChallengeStoreModule", () => {
	it("has the canonical module name 'redis-challenge-store'", () => {
		expect(redisChallengeStoreModule.name).toBe("redis-challenge-store");
	});

	it("requires both 'redisClient' and 'config'", () => {
		const reqs = redisChallengeStoreModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["redisClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisChallengeStore' top-level key only", () => {
		expect(redisChallengeStoreModule.configSchema).toBeDefined();
		// Validate parsed shape via direct schema parse with empty input —
		// default keyPrefix "chal:" should be applied.
		const parsed = redisChallengeStoreModule.configSchema?.parse({}) as {
			redisChallengeStore?: { keyPrefix?: string };
		};
		expect(parsed?.redisChallengeStore?.keyPrefix).toBe("chal:");
	});
});

describe("redisReplaySeenSetModule", () => {
	it("has the canonical module name 'redis-replay-seen-set'", () => {
		expect(redisReplaySeenSetModule.name).toBe("redis-replay-seen-set");
	});

	it("requires both 'redisClient' and 'config'", () => {
		const reqs = redisReplaySeenSetModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["redisClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisReplaySeenSet' top-level key only", () => {
		expect(redisReplaySeenSetModule.configSchema).toBeDefined();
		const parsed = redisReplaySeenSetModule.configSchema?.parse({}) as {
			redisReplaySeenSet?: { keyPrefix?: string };
		};
		expect(parsed?.redisReplaySeenSet?.keyPrefix).toBe("replay:");
	});
});
