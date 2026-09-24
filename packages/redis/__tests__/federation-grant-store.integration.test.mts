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

// The Redis `FederationGrantStore` against the shared contract (#593, D16),
// on a real Redis.
//
// Two connections, and the contract alternates between two store instances
// over them: the races the suite sets up are then races across sockets, which
// is what a deployment has, rather than two calls into one client.

import type { FederationGrantStore } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll } from "vitest";
import { createRedisFederationGrantStore } from "../src/federation-grant-store.mjs";
import { makeIoredisFederationGrantStoreClient } from "../src/ioredis.mjs";
import { runFederationGrantStoreContract } from "./adapters.federation-grant-store.contract.mjs";
import { testRedis } from "./support/redis.mjs";

let connections: Redis[] = [];
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	connections = [new Redis(at), new Redis(at)];
});

afterAll(async () => {
	await Promise.all(connections.map((connection) => connection.quit()));
});

const key = (byte: number): Buffer => Buffer.alloc(32, byte);

/**
 * One store per connection, sharing the case's keyspace, and every call taken
 * in turn. The contract's concurrent writes then leave one socket while the
 * other is still in flight.
 */
const alternating = (keyPrefix: string): FederationGrantStore => {
	const stores = connections.map((connection) =>
		createRedisFederationGrantStore({
			client: makeIoredisFederationGrantStoreClient(connection),
			keyPrefix,
			encryption: { mode: "required", keys: [{ id: "k-1", key: key(1) }] },
		}),
	);
	let next = 0;
	const pick = (): FederationGrantStore => {
		const store = stores[next % stores.length] as FederationGrantStore;
		next += 1;
		return store;
	};
	return {
		kind: "redis",
		createPending: (input) => pick().createPending(input),
		nameIntent: (input) => pick().nameIntent(input),
		isCurrentIntent: (id, handle, now) => pick().isCurrentIntent(id, handle, now),
		retireIntent: (input) => pick().retireIntent(input),
		find: (id, now) => pick().find(id, now),
		listBySubject: (subject, now) => pick().listBySubject(subject, now),
		inspect: (id, now) => pick().inspect(id, now),
		open: (id, now) => pick().open(id, now),
		activate: (input) => pick().activate(input),
		replaceCredentials: (input) => pick().replaceCredentials(input),
		requireReauthorization: (input) => pick().requireReauthorization(input),
		revoke: (id, by, at) => pick().revoke(id, by, at),
		noteRefreshFailure: (input) => pick().noteRefreshFailure(input),
		touch: (id, at) => pick().touch(id, at),
		acquireRefreshLock: (id, bounds) => pick().acquireRefreshLock(id, bounds),
	};
};

let prefix = "";

runFederationGrantStoreContract("redis", {
	create: async () => {
		run += 1;
		prefix = `fgc${run}:`;
		return alternating(prefix);
	},
	teardown: async () => {
		// Only this case's keyspace, and only once its writes have settled.
		const connection = connections[0] as Redis;
		const keys = await connection.keys(`${prefix}*`);
		if (keys.length > 0) await connection.del(...keys);
	},
	// From outside the port, as the factory's contract asks: whether the
	// credential key exists at all, and not what the port says about it.
	credentialResident: async (_store, grantId) => {
		const connection = connections[0] as Redis;
		const id = Buffer.from(JSON.stringify(grantId), "utf8").toString("base64url");
		return (await connection.exists(`${prefix}{${id}}:cred`)) === 1;
	},
});
