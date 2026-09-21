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

// The Redis `FederationGrantIntentStore` against the shared contract (#593,
// D16, slice 6), on a real Redis.
//
// Two connections, and the contract alternates between two store instances
// over them: the races the suite sets up are then races across sockets, which
// is what a deployment has, rather than two calls into one client.

import type { FederationGrantIntentStore } from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisFederationGrantIntentStore } from "../src/federation-grant-intent-store.mjs";
import { federationGrantIntentPairText } from "../src/internal/federation-grant-intent-codec.mjs";
import { makeIoredisFederationGrantIntentStoreClient } from "../src/ioredis.mjs";
import { runFederationGrantIntentStoreContract } from "./adapters.federation-grant-intent-store.contract.mjs";

let container: StartedTestContainer;
let connections: Redis[] = [];
let run = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	const at = { host: container.getHost(), port: container.getMappedPort(6379) };
	connections = [new Redis(at), new Redis(at)];
}, 90_000);

afterAll(async () => {
	await Promise.all(connections.map((connection) => connection.quit()));
	await container?.stop();
});

/** How the adapter spells a value inside a key — looked at from outside, as the probes must. */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/**
 * One store per connection, sharing the case's keyspace, and every call taken
 * in turn. The contract's concurrent writes then leave one socket while the
 * other is still in flight.
 */
const alternating = (keyPrefix: string): FederationGrantIntentStore => {
	const stores = connections.map((connection) =>
		createRedisFederationGrantIntentStore({
			client: makeIoredisFederationGrantIntentStoreClient(connection),
			keyPrefix,
		}),
	);
	let next = 0;
	const pick = (): FederationGrantIntentStore => {
		const store = stores[next % stores.length] as FederationGrantIntentStore;
		next += 1;
		return store;
	};
	return {
		kind: "redis",
		putIntent: (record, now) => pick().putIntent(record, now),
		getIntent: (handle, now) => pick().getIntent(handle, now),
		parkConsent: (input) => pick().parkConsent(input),
		getConsent: (challenge, now) => pick().getConsent(challenge, now),
		answerConsent: (input) => pick().answerConsent(input),
		consumeTransaction: (input) => pick().consumeTransaction(input),
		finishIntent: (handle, now) => pick().finishIntent(handle, now),
	};
};

let prefix = "";
const space = (): string => `${prefix}{intents}:`;
const first = (): Redis => connections[0] as Redis;

runFederationGrantIntentStoreContract("redis", {
	create: async () => {
		run += 1;
		prefix = `fgi${run}:`;
		return alternating(prefix);
	},
	teardown: async () => {
		// Only this case's keyspace, and only once its writes have settled.
		const keys = await first().keys(`${prefix}*`);
		if (keys.length > 0) await first().del(...keys);
	},
	// From outside the port, as the factory's contract asks: whether the key is
	// THERE, not what the port says about it.
	intentResident: async (_store, handle) =>
		(await first().exists(`${space()}i:${keyPart(handle)}`)) === 1,
	consentResident: async (_store, challenge) =>
		(await first().exists(`${space()}c:${keyPart(challenge)}`)) === 1,
	transactionResident: async (_store, state) =>
		(await first().exists(`${space()}tx:${keyPart(state)}`)) === 1,
	// On the server's clock, which is the adapter's: a member whose deadline
	// Redis has passed is not a place held, whether or not a script pruned it.
	reservations: async (_store, clientId, subject) => {
		const [seconds, micros] = await first().time();
		const serverMs = Number(seconds) * 1000 + Math.floor(Number(micros) / 1000);
		const key = `${space()}r:${keyPart(federationGrantIntentPairText(clientId, subject))}`;
		return await first().zcount(key, `(${serverMs}`, "+inf");
	},
});

describe("the Redis intent store's layout", () => {
	it("keeps every key of one flow in the {intents} slot, and none of a grant's", async () => {
		run += 1;
		prefix = `fgl${run}:`;
		const store = alternating(prefix);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + 600_000);
		await store.putIntent(
			{
				handle: "h-1",
				kind: "initial",
				grantId: "g-1",
				clientId: "agent",
				subject: "u-1",
				connection: "okta-calendar",
				federation: "okta",
				identityRevision: "identity-1",
				authorizationRevision: "authorization-1",
				callbackUri: "https://provider.test/session/federation-grants/callback/okta-calendar",
				scopes: ["openid", "offline_access"],
				authorizationParams: {},
				redirectUri: "https://client.test/connected",
				clientState: "state-1",
				lifetimeMs: 86_400_000,
				createdAt: now,
				expiresAt,
				correlationId: "corr-1",
			},
			now,
		);
		const binding = { sessionId: "express-1", sid: "sid-1", subject: "u-1" };
		await store.parkConsent({ handle: "h-1", challenge: "c-1", binding, now });
		await store.answerConsent({
			challenge: "c-1",
			binding,
			answer: { decision: "accept", state: "s-1", codeVerifier: "v-1", nonce: "n-1" },
			now,
		});

		const keys = await first().keys(`${prefix}*`);
		expect(keys.length).toBeGreaterThan(0);
		for (const key of keys) expect(key.startsWith(`${prefix}{intents}:`)).toBe(true);
		// Every key carries a deadline: nothing a flow writes outlives it for good.
		for (const key of keys) expect(await first().pttl(key)).toBeGreaterThan(0);
		await first().del(...keys);
	});

	it("refuses a key prefix that would open a hash tag of its own", () => {
		expect(() =>
			createRedisFederationGrantIntentStore({
				client: makeIoredisFederationGrantIntentStoreClient(first()),
				keyPrefix: "fg{x}:",
			}),
		).toThrow(RangeError);
	});
});
