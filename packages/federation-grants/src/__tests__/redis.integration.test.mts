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

/**
 * The routes over a durable store, on a real Redis (#593, D16).
 *
 * Deliberately narrow: **only what the in-memory adapter cannot prove.** The
 * behavioural suites run against memory and the real retrieval function, and
 * duplicating them here would buy nothing but minutes. What memory cannot show
 * is everything that follows from a credential being sealed and a record
 * outliving the process that wrote it:
 *
 *  - a grant survives the adapter that created it;
 *  - a key that is not in the ring is an outage, and putting it back ends the
 *    outage — nothing was deleted meanwhile;
 *  - key material that is wrong under a known id is not an outage but an
 *    unreadable credential, and the record and the ciphertext are still there;
 *  - a tombstone answers `/status` after the grant has ended;
 *  - two processes sharing one grant refresh it once between them.
 *
 * Slice 3's own suites keep the contract, the key layout, the tampering
 * defences and the parity test. Nothing here reaches into the keyspace.
 */

import type {
	AuditEvent,
	AuditSink,
	Client,
	ClientRepository,
	FederationGrantRefresher,
	FederationGrantStore,
} from "@o3co/auth-provider-core";
import {
	createMemoryRateLimiter,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	resolveFederationGrantRetrievalLimits,
} from "@o3co/auth-provider-core";
import {
	createRedisFederationGrantStore,
	type FederationGrantKey,
} from "@o3co/auth-provider-redis";
// The vendor-facing half lives at its own subpath so the main entry stays
// vendor-agnostic; a deployment on another driver imports neither.
import { makeIoredisFederationGrantStoreClient } from "@o3co/auth-provider-redis/ioredis";
import express from "express";
import { Redis } from "ioredis";
import request from "supertest";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createFederationGrantBackground } from "#/background.mjs";
import { createFederationGrantRouter } from "#/routes.mjs";
import { FEDERATION_GRANTS_MOUNT_PATH } from "#/types.mjs";
import {
	basic,
	CLIENT_ID,
	CLIENT_SECRET,
	connection,
	DAY,
	MIN,
	SCOPES,
	SUBJECT,
} from "./harness.mjs";

let container: StartedTestContainer;
let connections: Redis[] = [];
let namespace = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	const at = { host: container.getHost(), port: container.getMappedPort(6379) };
	connections = [new Redis(at), new Redis(at)];
}, 90_000);

afterAll(async () => {
	await Promise.all(connections.map((c) => c.quit()));
	await container?.stop();
});

const material = (byte: number): Buffer => Buffer.alloc(32, byte);
const KEY_ONE: FederationGrantKey = { id: "k-1", key: material(1) };

const client = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [],
	allowedFederationGrantConnections: [connection.name],
} as unknown as Client;

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? (client as never) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? (client as never) : null,
};

interface Deployment {
	readonly app: express.Express;
	readonly store: FederationGrantStore;
	readonly refresh: ReturnType<typeof vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>>;
	readonly events: AuditEvent[];
	readonly drain: () => Promise<void>;
}

/**
 * One process: its own connection, its own store instance over the shared
 * keyspace, its own routes. Two of these is two replicas.
 */
const deployment = (
	keyPrefix: string,
	keys: readonly FederationGrantKey[],
	which = 0,
	tombstoneRetentionMs?: number,
): Deployment => {
	const store = createRedisFederationGrantStore({
		client: makeIoredisFederationGrantStoreClient(connections[which % connections.length] as Redis),
		keyPrefix,
		encryption: { mode: "required", keys: [...keys] },
		...(tombstoneRetentionMs === undefined ? {} : { tombstoneRetentionMs }),
	});
	const refresh = vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>();
	const events: AuditEvent[] = [];
	const background = createFederationGrantBackground();
	const sink: AuditSink = {
		kind: "test",
		record: async (event) => {
			events.push(event);
		},
	};
	const app = express();
	app.use(
		FEDERATION_GRANTS_MOUNT_PATH,
		createFederationGrantRouter({
			store,
			connections: new Map([[connection.name, connection]]),
			refresher: () => ({ refreshDelegatedToken: refresh }),
			grantsBoundary: async () => null,
			limits: resolveFederationGrantRetrievalLimits({ federationGrants: {} }),
			background,
			clientRepository,
			issuer: "https://auth.test",
			auditSink: sink,
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 1000, windowSeconds: 60 },
			}),
			failMode: "closed",
		}),
	);
	return { app, store, refresh, events, drain: () => background.drain() };
};

/** A live grant with an access token that has run down, so a refresh is due. */
const seed = async (store: FederationGrantStore, spent = false): Promise<void> => {
	const at = new Date();
	await store.createPending({
		id: "g-1",
		subject: SUBJECT,
		clientId: CLIENT_ID,
		connection: connection.name,
		intent: { handle: "h", expiresAt: new Date(at.getTime() + 10 * MIN) },
		now: at,
	});
	await store.activate({
		grantId: "g-1",
		intentHandle: "h",
		authorization: {
			identityRevision: federationGrantIdentityRevision(connection),
			authorizationRevision: federationGrantAuthorizationRevision(connection),
			upstream: { issuer: connection.upstreamIssuer, subject: "upstream-subject" },
			scopes: [...SCOPES],
			consent: { at, sid: "sid", scopes: [...SCOPES] },
			authorizedAt: at,
			expiresAt: new Date(at.getTime() + 30 * DAY),
			resource: undefined,
		},
		credentials: {
			refreshToken: "upstream-refresh-token",
			accessToken: {
				value: "stored-access-token",
				tokenType: "Bearer",
				// Spent: obtained an hour ago of an hour's life, so it is past half
				// spent and inside the refresh buffer.
				obtainedAt: spent ? new Date(at.getTime() - 3_600_000) : at,
				issuedLifetime: 3600,
				scopes: [...SCOPES],
			},
		},
		now: at,
	});
};

const token = (d: Deployment) =>
	request(d.app)
		.post("/oauth/federation-grants/g-1/token")
		.set("Authorization", basic())
		.send({ sub: SUBJECT });

const status = (d: Deployment) =>
	request(d.app)
		.post("/oauth/federation-grants/g-1/status")
		.set("Authorization", basic())
		.send({ sub: SUBJECT });

describe("the routes over a durable store", () => {
	it("answers about a grant the process that created it never saw", async () => {
		// The point of a durable store: a grant made before a deploy is spent
		// after it, by a process with nothing in memory.
		const prefix = `fg-restart-${namespace++}:`;
		await seed(deployment(prefix, [KEY_ONE]).store);

		const fresh = deployment(prefix, [KEY_ONE], 1);
		const disclosed = await token(fresh);
		expect(disclosed.status).toBe(200);
		expect(disclosed.body.access_token).toBe("stored-access-token");

		const described = await status(fresh);
		expect(described.status).toBe(200);
		expect(described.body).toMatchObject({ status: "active", sub: SUBJECT });
	});

	it("treats a key that is not in the ring as an outage, on both routes", async () => {
		const prefix = `fg-key-${namespace++}:`;
		await seed(deployment(prefix, [KEY_ONE]).store);

		// The same records, read by a process whose ring never had the key.
		const without = deployment(prefix, [{ id: "k-2", key: material(2) }], 1);
		expect((await token(without)).body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});
		expect((await status(without)).body).toEqual({
			error: "temporarily_unavailable",
			error_description: "key_unavailable",
		});

		// Nothing was deleted because it could not be read: putting the key
		// back is the whole of the remedy.
		const restored = deployment(prefix, [KEY_ONE, { id: "k-2", key: material(2) }]);
		expect((await token(restored)).status).toBe(200);
		expect((await status(restored)).body.status).toBe("active");
	});

	it("treats wrong material under a known id as an unreadable credential, and keeps the record", async () => {
		// Different from a missing key, and answered differently: this one does
		// not come back by restoring anything an operator still has, so the
		// user is asked again — after the key material has been investigated.
		const prefix = `fg-material-${namespace++}:`;
		await seed(deployment(prefix, [KEY_ONE]).store);

		const wrong = deployment(prefix, [{ id: "k-1", key: material(9) }], 1);
		const disclosed = await token(wrong);
		expect(disclosed.status).toBe(410);
		expect(disclosed.body).toEqual({
			error: "reauthorization_required",
			error_description: "credential_unreadable",
		});

		// The record is still there, and so is the credential: the right
		// material still opens it.
		const right = deployment(prefix, [KEY_ONE]);
		expect((await token(right)).status).toBe(200);
	});

	it("describes a grant that has ended for as long as its tombstone is kept", async () => {
		const prefix = `fg-tombstone-${namespace++}:`;
		const first = deployment(prefix, [KEY_ONE]);
		await seed(first.store);
		await first.store.revoke("g-1", "subject", new Date());

		// A process that has never seen the grant still answers about it —
		// which is what makes "why did this stop working?" answerable at all.
		// How LONG it answers is the stored retention, and that is slice 3's
		// test: it cannot be observed here without waiting a month.
		const later = deployment(prefix, [KEY_ONE], 1);
		const described = await status(later);
		expect(described.status).toBe(200);
		expect(described.body).toMatchObject({ status: "revoked", reason: "subject" });

		// And the token route says the same thing in its own vocabulary.
		expect((await token(later)).status).toBe(410);
	});

	it("lets two processes sharing one grant refresh it once between them", async () => {
		// The lock is the only thing that stops both from presenting the same
		// refresh token to an IdP that rotates — which that IdP answers by
		// revoking the family.
		const prefix = `fg-race-${namespace++}:`;
		const one = deployment(prefix, [KEY_ONE], 0);
		const two = deployment(prefix, [KEY_ONE], 1);
		await seed(one.store, true);

		const rotated = {
			accessToken: "rotated-access-token",
			refreshToken: "rotated-refresh-token",
			expiresIn: 3600,
			expiresAt: new Date(Date.now() + 3_600_000),
			tokenType: "Bearer",
		};
		one.refresh.mockResolvedValue(rotated);
		two.refresh.mockResolvedValue(rotated);

		const [a, b] = await Promise.all([token(one), token(two)]);

		expect(a.status).toBe(200);
		expect(b.status).toBe(200);
		// Exactly one upstream round trip between the two processes, and both
		// answers are the winner's stored state.
		expect(one.refresh.mock.calls.length + two.refresh.mock.calls.length).toBe(1);
		expect(a.body.access_token).toBe("rotated-access-token");
		expect(b.body.access_token).toBe("rotated-access-token");

		await Promise.all([one.drain(), two.drain()]);
	});
});
