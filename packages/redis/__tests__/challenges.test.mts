/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll } from "vitest";
import { createRedisChallengeStore } from "../src/challenges.mjs";
import type { ChallengeStoreClient } from "../src/clients.mjs";
import { runChallengeStoreContract } from "./adapters.challenge-store.contract.mjs";

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

runChallengeStoreContract("redis", {
	create: () => {
		// Per-test prefix isolation so concurrency tests do not collide across
		// shared container state.
		keyCounter += 1;
		return createRedisChallengeStore({
			client: client as unknown as ChallengeStoreClient,
			keyPrefix: `chal:test-${keyCounter}:`,
		});
	},
});
