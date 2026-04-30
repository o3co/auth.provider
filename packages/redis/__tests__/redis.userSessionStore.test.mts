/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { afterAll, beforeAll } from "vitest";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import Redis from "ioredis";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";
import { runUserSessionStoreContract } from "./userSessionStore.contract.mjs";
import { makeIoredisRedisClient } from "./helpers/wrapper.mjs"; // shared wrapper helper (Task 14.3)

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

let suiteCounter = 0;
runUserSessionStoreContract(async () => {
	suiteCounter += 1;
	const client = makeIoredisRedisClient(raw);
	return createRedisUserSessionStore({ client, keyPrefix: `t14:${suiteCounter}:` });
});
