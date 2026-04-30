/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll } from "vitest";
import { createRedisReplaySeenSet } from "../src/replay-seen-set.mjs";
import type { RedisClient } from "../src/types.mjs";
import { runReplaySeenSetContract } from "./adapters.replay-seen-set.contract.mjs";

let container: StartedTestContainer;
let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 60_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

runReplaySeenSetContract("redis", {
	create: () => {
		keyCounter += 1;
		return createRedisReplaySeenSet({
			client: client as unknown as RedisClient,
			keyPrefix: `replay:test-${keyCounter}:`,
		});
	},
});
