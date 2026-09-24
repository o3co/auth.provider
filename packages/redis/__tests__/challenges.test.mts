/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import Redis from "ioredis";
import { afterAll, beforeAll } from "vitest";
import { createRedisChallengeStore } from "../src/challenges.mjs";
import type { ChallengeStoreClient } from "../src/clients.mjs";
import { runChallengeStoreContract } from "./adapters.challenge-store.contract.mjs";
import { keysExpire, testRedis } from "./support/redis.mjs";

let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	client = new Redis(at);
});

afterAll(async () => {
	await client?.quit();
});

runChallengeStoreContract(
	"redis",
	{
		create: () => {
			// Per-test prefix isolation so concurrency tests do not collide across
			// shared container state.
			keyCounter += 1;
			return createRedisChallengeStore({
				client: client as unknown as ChallengeStoreClient,
				keyPrefix: `chal:test-${keyCounter}:`,
			});
		},
	},
	{
		// A relative PX: the challenge is gone when its key is.
		expiry: keysExpire(
			() => client,
			() => `chal:test-${keyCounter}:`,
		),
	},
);
