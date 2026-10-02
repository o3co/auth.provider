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

// The rotation budget in the Redis federation grant store, against a real
// Redis: the hash fields `rotationsSince` / `rotationsCount` read as the
// grant's `rotations` on every read, a record without them (or with ones that
// do not parse) as no window, and a refresh through the store keeps them.

import {
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantCredentialsInput,
	type FederationGrantStore,
	hasFederationGrantAuthorization,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FederationGrantStoreClient } from "#/clients.mjs";
import { createRedisFederationGrantStore } from "#/federation-grant-store.mjs";
import { makeIoredisFederationGrantStoreClient } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let redis: Redis;
let run = 0;

beforeAll(async () => {
	redis = new Redis(await testRedis());
});

afterAll(async () => {
	await redis?.quit();
});

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

let prefix = "";
let T0 = new Date();
const at = (ms: number): Date => new Date(T0.getTime() + ms);

beforeEach(() => {
	run += 1;
	prefix = `fgr${run}:`;
	T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
});

const storeOver = (client: FederationGrantStoreClient): FederationGrantStore =>
	createRedisFederationGrantStore({
		client,
		keyPrefix: prefix,
		encryption: { mode: "required", keys: [{ id: "k-1", key: Buffer.alloc(32, 1) }] },
	});

const store = (): FederationGrantStore => storeOver(makeIoredisFederationGrantStoreClient(redis));

const grantKey = (id: string): string =>
	`${prefix}{${Buffer.from(JSON.stringify(id), "utf8").toString("base64url")}}:grant`;

const SCOPES = ["openid", "offline_access"];
const authorization = (): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	resource: undefined,
	scopes: [...SCOPES],
	consent: { at: at(MIN), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(2 * MIN),
	expiresAt: at(30 * DAY),
});

const credentials = (tag: string): FederationGrantCredentialsInput => ({
	refreshToken: `rt-${tag}`,
	accessToken: {
		value: `at-${tag}`,
		tokenType: "Bearer",
		obtainedAt: at(2 * MIN),
		issuedLifetime: 3600,
		effectiveExpiresAt: at(62 * MIN),
		scopes: [...SCOPES],
	},
});

/** A grant taken to `active` (version 2). */
const activated = async (held: FederationGrantStore, id = "g-1"): Promise<FederationGrant> => {
	await held.createPending({
		id,
		subject: "u-1",
		clientId: "agent",
		connection: "okta-calendar",
		intent: { handle: `h-${id}`, expiresAt: at(10 * MIN) },
		now: T0,
	});
	const written = await held.activate({
		grantId: id,
		intentHandle: `h-${id}`,
		authorization: authorization(),
		credentials: credentials("1"),
		now: at(2 * MIN),
	});
	if (!written.ok) throw new Error("fixture: the activation did not succeed");
	return written.grant;
};

/** The grant as each read of the port answers it: they must all agree. */
const everyRead = async (held: FederationGrantStore, now: Date): Promise<unknown[]> => [
	await held.find("g-1", now),
	(await held.listBySubject("u-1", now))[0],
	(await held.inspect("g-1", now))?.grant,
	(await held.open("g-1", now))?.grant,
];

describe("the rotation budget's fields", () => {
	it("read back as the grant's rotations, from every read", async () => {
		const held = store();
		const grant = await activated(held);
		const taken = await held.takeRotation?.({
			grantId: "g-1",
			expectedVersion: grant.version,
			limit: 3,
			windowMs: HOUR,
			now: at(DAY),
		});
		const rotations = { since: at(DAY), count: 1 };
		expect(taken).toMatchObject({ ok: true, grant: { rotations } });
		expect(await redis.hmget(grantKey("g-1"), "rotationsSince", "rotationsCount")).toEqual([
			String(at(DAY).getTime()),
			"1",
		]);
		for (const read of await everyRead(held, at(DAY))) {
			expect(read).toMatchObject({ rotations });
		}
	});

	it("are no key at all on a record without them, and on one whose fields do not parse", async () => {
		const held = store();
		await activated(held);
		for (const read of await everyRead(held, at(DAY))) {
			expect(read).not.toHaveProperty("rotations");
		}
		for (const fields of [
			{ rotationsSince: String(at(DAY).getTime()) },
			{ rotationsCount: "1" },
			{ rotationsSince: String(at(DAY).getTime()), rotationsCount: "0" },
			{ rotationsSince: String(at(DAY).getTime()), rotationsCount: "1e0" },
			{ rotationsSince: "soon", rotationsCount: "1" },
			{ rotationsSince: "9007199254740993", rotationsCount: "1" },
		]) {
			await redis.hdel(grantKey("g-1"), "rotationsSince", "rotationsCount");
			await redis.hset(grantKey("g-1"), fields);
			for (const read of await everyRead(held, at(DAY))) {
				expect(read, JSON.stringify(fields)).not.toHaveProperty("rotations");
			}
		}
	});

	it("are kept by a refresh through the store, on the record and in what it answers", async () => {
		const held = store();
		const grant = await activated(held);
		await held.takeRotation?.({
			grantId: "g-1",
			expectedVersion: grant.version,
			limit: 3,
			windowMs: HOUR,
			now: at(DAY),
		});
		const replaced = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: grant.version,
			credentials: credentials("2"),
			ineligible: null,
			now: at(DAY + MIN),
		});
		if (!replaced.ok || !hasFederationGrantAuthorization(replaced.grant)) {
			throw new Error("fixture: the refresh did not write");
		}
		expect(replaced.grant.rotations).toStrictEqual({ since: at(DAY), count: 1 });
		expect(await redis.hmget(grantKey("g-1"), "rotationsSince", "rotationsCount")).toEqual([
			String(at(DAY).getTime()),
			"1",
		]);
	});
});

describe("a client without takeRotation", () => {
	it("gives a store without the member, which keeps no rotation budget", () => {
		const { takeRotation: _, ...rest } = makeIoredisFederationGrantStoreClient(redis);
		expect(storeOver(rest).takeRotation).toBeUndefined();
		expect(store().takeRotation).toBeTypeOf("function");
	});
});

describe("takeRotation's bounds", () => {
	it("are refused with a RangeError before anything is sent", async () => {
		let sent = 0;
		const client = makeIoredisFederationGrantStoreClient(redis);
		const counting: FederationGrantStoreClient = {
			...client,
			async snapshot(...args) {
				sent += 1;
				return await client.snapshot(...args);
			},
			async takeRotation(...args) {
				sent += 1;
				return (await client.takeRotation?.(...args)) ?? null;
			},
		};
		const held = storeOver(counting);
		for (const bounds of [
			{ limit: 0, windowMs: HOUR },
			{ limit: 1.5, windowMs: HOUR },
			{ limit: 1, windowMs: 0 },
			{ limit: 1, windowMs: Number.NaN },
		]) {
			await expect(
				held.takeRotation?.({ grantId: "g-1", expectedVersion: 2, now: at(DAY), ...bounds }),
				JSON.stringify(bounds),
			).rejects.toThrow(RangeError);
		}
		await expect(
			held.takeRotation?.({
				grantId: "g-1",
				expectedVersion: 2,
				limit: 1,
				windowMs: HOUR,
				now: new Date(Number.NaN),
			}),
		).rejects.toThrow(RangeError);
		expect(sent).toBe(0);
	});

	it("count a fractional window as the whole milliseconds it spans: instants are whole", async () => {
		const held = store();
		const grant = await activated(held);
		const take = (now: Date) =>
			held.takeRotation?.({
				grantId: "g-1",
				expectedVersion: grant.version,
				limit: 1,
				windowMs: 0.5,
				now,
			});
		expect((await take(at(DAY)))?.ok).toBe(true);
		// 0.5 ms on: the next whole instant is already past the window.
		expect(await take(at(DAY + 1))).toMatchObject({
			ok: true,
			grant: { rotations: { since: at(DAY + 1), count: 1 } },
		});
		expect(await take(at(DAY + 1))).toEqual({ ok: false });
	});
});
