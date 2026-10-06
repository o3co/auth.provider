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

// The Redis FederationTokenStore held to `federationTokenStoreConditionalContract`
// on a real Redis: two stores on two connections sharing one key prefix, so
// the races and the cross-instance case prove the fence across processes. A
// record's expiry is brought forward by `PEXPIRE`, and the outage is a store on
// a connection that never connects and queues nothing.

import { federationTokenStoreConditionalContract } from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, it } from "vitest";
import { createRedisFederationTokenStore } from "#/federation-tokens.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { EXPIRY_GRACE_MS, testRedis, until } from "./support/redis.mjs";

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

/** A store over `io`; `durable` stands in for a server that cannot answer the gate. */
const storeOn = (io: Redis, keyPrefix: string, durable = false) => {
	const client = makeIoredisClients(io).federationTokenStoreClient;
	return createRedisFederationTokenStore({
		deploymentMode: "unset",
		client: durable
			? {
					...client,
					durability: async () => ({
						maxmemoryPolicy: "noeviction",
						appendOnly: undefined,
						snapshots: undefined,
						refusal: undefined,
					}),
				}
			: client,
		encryption: { mode: "required", key: Buffer.alloc(32, 9) },
		keyPrefix,
		scanFallback: false,
	});
};

describe("federationTokenStoreConditionalContract over the Redis store, on two connections", () => {
	for (const contractCase of federationTokenStoreConditionalContract({
		build: async () => {
			harnesses += 1;
			const keyPrefix = `ftcw:${harnesses}:`;
			const offline = one.duplicate({ lazyConnect: true, enableOfflineQueue: false });
			const unreachable = await storeOn(offline, keyPrefix, true);
			return {
				store: await storeOn(one, keyPrefix),
				second: await storeOn(two, keyPrefix),
				forceExpire: async (sid, federationName) => {
					const key = `${keyPrefix}${sid}:${federationName}`;
					await one.pexpire(key, 1);
					await until(
						async () => (await one.pttl(key)) === -2,
						`${key} to expire`,
						Date.now() + EXPIRY_GRACE_MS,
					);
				},
				unreachable: () => unreachable,
			};
		},
		supports: { forceExpire: true, unreachable: true },
	})) {
		it(contractCase.name, contractCase.run);
	}
});
