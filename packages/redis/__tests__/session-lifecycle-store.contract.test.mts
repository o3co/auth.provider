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

// The Redis SessionLifecycleStore held to `sessionLifecycleStoreContract` on a
// real Redis: two stores on two connections sharing one key prefix, so the
// races and the cross-instance cases prove the fence across processes. The
// outage is a store on a connection that never connects and queues nothing.
//
// The store judges every time on the server's clock, which a test cannot
// move, so the clock and retention cases are not declared; the adapter's own
// tests hold its retention and its lapse (session-lifecycle-store.test.mts).

import { sessionLifecycleStoreContract } from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, it } from "vitest";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisSessionLifecycleStore } from "#/session-lifecycle-store.mjs";
import { testRedis } from "./support/redis.mjs";

let one: Redis;
let two: Redis;

beforeAll(async () => {
	const at = await testRedis();
	one = new Redis(at);
	two = new Redis(at);
});

afterAll(() => {
	one?.disconnect();
	two?.disconnect();
});

let harnesses = 0;

const storeOn = (io: Redis, keyPrefix: string) =>
	createRedisSessionLifecycleStore({
		client: makeIoredisClients(io).sessionLifecycleStoreClient,
		keyPrefix,
	});

describe("sessionLifecycleStoreContract over the Redis store, on two connections", () => {
	for (const contractCase of sessionLifecycleStoreContract({
		build: async () => {
			harnesses += 1;
			const keyPrefix = `lcc:${harnesses}:`;
			return {
				store: storeOn(one, keyPrefix),
				second: storeOn(two, keyPrefix),
				unreachable: () => {
					const offline = one.duplicate({ lazyConnect: true, enableOfflineQueue: false });
					return storeOn(offline, keyPrefix);
				},
			};
		},
		supports: { unreachable: true },
	})) {
		it(contractCase.name, contractCase.run);
	}
});
