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

import {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisFederationGrantIntentStore } from "../src/federation-grant-intent-store.mjs";
import { federationGrantIntentPairText } from "../src/internal/federation-grant-intent-codec.mjs";
import { makeIoredisFederationGrantIntentStoreClient } from "../src/ioredis.mjs";
import { runFederationGrantIntentStoreContract } from "./adapters.federation-grant-intent-store.contract.mjs";
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
				resource: undefined,
				authorizationParams: {},
				redirectUri: "https://client.test/connected",
				clientState: "state-1",
				upstreamSubject: undefined,
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

// ---------------------------------------------------------------------------
// What only Redis can get wrong. Found by the mutation pass: each of these
// survived the shared contract, because the contract cannot reach a server
// clock, a key TTL, a race between an adapter's read and its script, or an
// eviction policy.
// ---------------------------------------------------------------------------

const fixture = (over: Partial<FederationGrantIntent> = {}): FederationGrantIntent => {
	const now = new Date();
	return {
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
		resource: undefined,
		authorizationParams: {},
		redirectUri: "https://client.test/connected",
		clientState: "state-1",
		upstreamSubject: undefined,
		lifetimeMs: 86_400_000,
		createdAt: now,
		expiresAt: new Date(now.getTime() + 600_000),
		correlationId: "corr-1",
		...over,
	};
};

const BINDING = { sessionId: "express-1", sid: "sid-1", subject: "u-1" };

const fresh = (tag: string): FederationGrantIntentStore => {
	run += 1;
	prefix = `${tag}${run}:`;
	return alternating(prefix);
};

const sweep = async (): Promise<void> => {
	const keys = await first().keys(`${prefix}*`);
	if (keys.length > 0) await first().del(...keys);
};

describe("the Redis intent store, where the contract cannot look", () => {
	it("releases a place on the SERVER's clock, with nobody asking", async () => {
		// Without the prune a lapsed flow would hold its place until the index
		// key itself expired — its last deadline plus the allowance, five minutes
		// during which the user could not connect at all.
		const store = fresh("fgp");
		const soon = new Date(Date.now() + 1_200);
		for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
			expect(
				(
					await store.putIntent(
						fixture({ handle: `h-${i}`, grantId: `g-${i}`, expiresAt: soon }),
						new Date(),
					)
				).outcome,
			).toBe("created");
		}
		expect(
			(await store.putIntent(fixture({ handle: "h-over", grantId: "g-over" }), new Date())).outcome,
		).toBe("refused");
		await new Promise((resolve) => setTimeout(resolve, 1_600));
		expect(
			(await store.putIntent(fixture({ handle: "h-after", grantId: "g-after" }), new Date()))
				.outcome,
		).toBe("created");
		await sweep();
	});

	it("gives a parked challenge the flow's deadline, as a key TTL", async () => {
		const store = fresh("fgt");
		const now = new Date();
		await store.putIntent(fixture(), now);
		await store.parkConsent({ handle: "h-1", challenge: "c-1", binding: BINDING, now });
		const keys = await first().keys(`${prefix}*`);
		expect(keys.some((key) => key.includes("}:c:"))).toBe(true);
		for (const key of keys) expect(await first().pttl(key)).toBeGreaterThan(0);
		await sweep();
	});

	it("does not park on an intent that was closed between the adapter's read and its script", async () => {
		// The adapter reads the intent to build the consent record, then the
		// script writes it. A finish landing between the two must win: the
		// script's own check is what sees it, so this puts the finish exactly
		// there rather than hoping two sockets interleave that way.
		run += 1;
		prefix = `fgr${run}:`;
		const real = makeIoredisFederationGrantIntentStoreClient(first());
		const store = createRedisFederationGrantIntentStore({
			keyPrefix: prefix,
			client: {
				...real,
				parkConsent: async (space, input) => {
					await real.finishIntent(space, input.handle, input.nowMs);
					return await real.parkConsent(space, input);
				},
			},
		});
		const now = new Date();
		await store.putIntent(fixture(), now);
		expect(
			await store.parkConsent({ handle: "h-1", challenge: "c-1", binding: BINDING, now }),
		).toBeNull();
		expect(await first().exists(`${space()}c:${keyPart("c-1")}`)).toBe(0);
		await sweep();
	});

	it("will not re-park a flow whose parked consent was dropped (Codex on slice 6)", async () => {
		// The intent's pointer says a challenge was issued; the key it names is
		// gone. Parking a fresh one would bind the flow to whichever browser
		// asked next, which the memory adapter refuses and so must this.
		const store = fresh("fgd");
		const now = new Date();
		await store.putIntent(fixture(), now);
		await store.parkConsent({ handle: "h-1", challenge: "c-1", binding: BINDING, now });
		await first().del(`${space()}c:${keyPart("c-1")}`);
		expect(
			await store.parkConsent({
				handle: "h-1",
				challenge: "c-2",
				binding: { sessionId: "express-2", sid: "sid-2", subject: "u-1" },
				now,
			}),
		).toBeNull();
		expect(await first().exists(`${space()}c:${keyPart("c-2")}`)).toBe(0);
		await sweep();
	});

	it("shows no consent whose intent is gone, whichever key Redis dropped first", async () => {
		// An eviction policy (allkeys-lru and the like) can take one key of a
		// flow and leave the other. A page shown a question for a flow that
		// cannot continue would collect an answer that goes nowhere.
		const store = fresh("fge");
		const now = new Date();
		await store.putIntent(fixture(), now);
		await store.parkConsent({ handle: "h-1", challenge: "c-1", binding: BINDING, now });
		await first().del(`${space()}i:${keyPart("h-1")}`);
		expect(await store.getConsent("c-1", now)).toBeNull();
		expect(
			await store.answerConsent({
				challenge: "c-1",
				binding: BINDING,
				answer: { decision: "deny" },
				now,
			}),
		).toEqual({ outcome: "empty" });
		await sweep();
	});
});

describe("a reservation allowance whose deadline no clock reaches (the Date range)", () => {
	it("is refused when the store is built, so no admission leaves the reservation index without a TTL", async () => {
		// The admission's script reserves the place and sets the index's
		// deadline last; 1e21 ms is sent as `1e+21`, which Redis refuses, and
		// the reservation it had just written was left with no TTL.
		run += 1;
		prefix = `fgd${run}:`;
		let refusal: unknown;
		try {
			const store = createRedisFederationGrantIntentStore({
				client: makeIoredisFederationGrantIntentStoreClient(first()),
				keyPrefix: prefix,
				reservationAllowanceMs: 1e21,
			});
			await store.putIntent(fixture(), new Date()).catch(() => undefined);
		} catch (err) {
			refusal = err;
		}
		const keys = await first().keys(`${prefix}*`);
		const withoutTtl: string[] = [];
		for (const name of keys) if ((await first().pttl(name)) < 0) withoutTtl.push(name);
		await sweep();
		expect(withoutTtl).toEqual([]);
		expect(refusal).toBeInstanceOf(RangeError);
	});

	it("is refused however far past it is, and one that ends inside it is taken", () => {
		const build = (reservationAllowanceMs: number) => () =>
			createRedisFederationGrantIntentStore({
				client: makeIoredisFederationGrantIntentStoreClient(first()),
				reservationAllowanceMs,
			});
		for (const bad of [8_640_000_000_000_001, 1e20, 1e21]) {
			expect(build(bad), String(bad)).toThrow(RangeError);
		}
		expect(build(31_536_000_000)).not.toThrow();
	});
});
