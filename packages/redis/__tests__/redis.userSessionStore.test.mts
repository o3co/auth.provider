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

import { Redis } from "ioredis";
import { afterAll, beforeAll } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";
import { keysExpire, testRedis } from "./support/redis.mjs";
import { runUserSessionStoreContract } from "./userSessionStore.contract.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

let suiteCounter = 0;
runUserSessionStoreContract(
	async () => {
		suiteCounter += 1;
		const { userSessionStoreClient } = makeIoredisClients(raw);
		return createRedisUserSessionStore({
			client: userSessionStoreClient,
			keyPrefix: `t14:${suiteCounter}:`,
		});
	},
	// A relative PX: the session is gone when its key is.
	keysExpire(
		() => raw,
		() => `t14:${suiteCounter}:`,
	),
);
