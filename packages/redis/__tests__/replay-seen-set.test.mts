/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import Redis from "ioredis";
import { afterAll, beforeAll } from "vitest";
import type { ReplaySeenSetClient } from "../src/clients.mjs";
import { createRedisReplaySeenSet } from "../src/replay-seen-set.mjs";
import { runReplaySeenSetContract } from "./adapters.replay-seen-set.contract.mjs";
import { testRedis } from "./support/redis.mjs";

let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	client = new Redis(at);
});

afterAll(async () => {
	await client?.quit();
});

runReplaySeenSetContract("redis", {
	create: () => {
		keyCounter += 1;
		return createRedisReplaySeenSet({
			client: client as unknown as ReplaySeenSetClient,
			keyPrefix: `replay:test-${keyCounter}:`,
		});
	},
});
