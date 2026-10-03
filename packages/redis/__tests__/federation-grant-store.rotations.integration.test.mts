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
// do not parse) as no window, a refresh through the store keeps them, and a
// give-back writes only the count and the version, on the record as it is.
// The refusals every adapter shares (another window, a stale version, a grant
// that is not active or is past its expiry) are the shared contract suite's,
// run here from `adapters.federation-grant-store.contract.mts`.

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
			{ rotationsSince: String(at(DAY).getTime()), rotationsCount: "-1" },
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
		// The take bumped the version: the refresh writes at the one it left.
		const replaced = await held.replaceCredentials({
			grantId: "g-1",
			expectedVersion: grant.version + 1,
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
		const take = (now: Date, expectedVersion: number) =>
			held.takeRotation?.({
				grantId: "g-1",
				expectedVersion,
				limit: 1,
				windowMs: 0.5,
				now,
			});
		expect((await take(at(DAY), grant.version))?.ok).toBe(true);
		// 0.5 ms on: the next whole instant is already past the window.
		expect(await take(at(DAY + 1), grant.version + 1)).toMatchObject({
			ok: true,
			grant: { rotations: { since: at(DAY + 1), count: 1 } },
		});
		expect(await take(at(DAY + 1), grant.version + 2)).toEqual({ ok: false });
	});
});

describe("refundRotation", () => {
	const takeAt = async (held: FederationGrantStore, version: number, now: Date) => {
		const taken = await held.takeRotation?.({
			grantId: "g-1",
			expectedVersion: version,
			limit: 3,
			windowMs: HOUR,
			now,
		});
		if (taken?.ok !== true) throw new Error("fixture: the take was refused");
		return taken;
	};
	const refundAt = (held: FederationGrantStore, version: number, since: Date, now: Date) =>
		held.refundRotation?.({ grantId: "g-1", expectedVersion: version, since, now });

	it("is offered only over a client that has the primitive", () => {
		const { refundRotation: _, ...rest } = makeIoredisFederationGrantStoreClient(redis);
		expect(storeOver(rest).refundRotation).toBeUndefined();
		expect(storeOver(rest).takeRotation).toBeTypeOf("function");
		expect(store().refundRotation).toBeTypeOf("function");
	});

	it("leaves a window counted down to none, read back from every read, which a take counts on into", async () => {
		const held = store();
		const grant = await activated(held);
		const taken = await takeAt(held, grant.version, at(DAY));
		expect(taken.grant.version).toBe(grant.version + 1);
		expect(await refundAt(held, grant.version + 1, at(DAY), at(DAY + MIN))).toMatchObject({
			ok: true,
			grant: { version: grant.version + 2, rotations: { since: at(DAY), count: 0 } },
		});
		expect(await redis.hmget(grantKey("g-1"), "rotationsSince", "rotationsCount")).toEqual([
			String(at(DAY).getTime()),
			"0",
		]);
		for (const read of await everyRead(held, at(DAY + MIN))) {
			expect(read).toMatchObject({ rotations: { since: at(DAY), count: 0 } });
		}
		expect(await takeAt(held, grant.version + 2, at(DAY + 2 * MIN))).toMatchObject({
			grant: { rotations: { since: at(DAY), count: 1 } },
		});
	});

	it("writes only the count and the version, and moves no deadline", async () => {
		const held = store();
		const grant = await activated(held);
		await takeAt(held, grant.version, at(DAY));
		const credKey = grantKey("g-1").replace(/:grant$/, ":cred");
		const before = await redis.hgetall(grantKey("g-1"));
		const deadlines = [await redis.pexpiretime(grantKey("g-1")), await redis.pexpiretime(credKey)];
		const credential = await redis.get(credKey);
		expect((await refundAt(held, grant.version + 1, at(DAY), at(DAY + MIN)))?.ok).toBe(true);
		expect(await redis.hgetall(grantKey("g-1"))).toEqual({
			...before,
			version: String(grant.version + 2),
			rotationsCount: "0",
		});
		expect([await redis.pexpiretime(grantKey("g-1")), await redis.pexpiretime(credKey)]).toEqual(
			deadlines,
		);
		expect(await redis.get(credKey)).toBe(credential);
	});

	it("refuses a window whose fields are gone or do not parse, and a record whose version is gone, writing nothing", async () => {
		const held = store();
		const grant = await activated(held);
		await takeAt(held, grant.version, at(DAY));
		const taken = await redis.hgetall(grantKey("g-1"));
		for (const [field, value] of [
			["rotationsSince", undefined],
			["rotationsCount", undefined],
			["rotationsCount", "1e0"],
			["rotationsCount", "-1"],
			["rotationsSince", "soon"],
			["version", undefined],
			["version", "two"],
		] as const) {
			await redis.del(grantKey("g-1"));
			await redis.hset(grantKey("g-1"), taken);
			if (value === undefined) await redis.hdel(grantKey("g-1"), field);
			else await redis.hset(grantKey("g-1"), field, value);
			const stored = await redis.hgetall(grantKey("g-1"));
			expect(
				await refundAt(held, grant.version + 1, at(DAY), at(DAY + MIN)),
				`${field}=${value}`,
			).toEqual({ ok: false });
			expect(await redis.hgetall(grantKey("g-1")), `${field}=${value}`).toEqual(stored);
		}
	});

	it("gives back once per version: of four give-backs at one version over two connections, one lands", async () => {
		const second = redis.duplicate();
		try {
			const held = store();
			const other = storeOver(makeIoredisFederationGrantStoreClient(second));
			const grant = await activated(held);
			await takeAt(held, grant.version, at(DAY));
			await takeAt(held, grant.version + 1, at(DAY + MIN));
			const results = await Promise.all(
				[held, other, held, other].map((each) =>
					refundAt(each, grant.version + 2, at(DAY), at(DAY + 2 * MIN)),
				),
			);
			expect(results.filter((result) => result?.ok === true)).toHaveLength(1);
			expect(await redis.hmget(grantKey("g-1"), "version", "rotationsCount")).toEqual([
				String(grant.version + 3),
				"1",
			]);
		} finally {
			second.disconnect();
		}
	});

	it("refuses a record whose key is gone mid-window, and does not bring it back", async () => {
		const held = store();
		const grant = await activated(held);
		await takeAt(held, grant.version, at(DAY));
		await redis.del(grantKey("g-1"));
		expect(await refundAt(held, grant.version + 1, at(DAY), at(DAY + MIN))).toEqual({ ok: false });
		expect(await redis.exists(grantKey("g-1"))).toBe(0);
	});

	it("refuses a version that is not a whole number without a round trip, and a time or window that is not a date with a RangeError before one", async () => {
		let sent = 0;
		const client = makeIoredisFederationGrantStoreClient(redis);
		const counting: FederationGrantStoreClient = {
			...client,
			async snapshot(...args) {
				sent += 1;
				return await client.snapshot(...args);
			},
			async refundRotation(...args) {
				sent += 1;
				return (await client.refundRotation?.(...args)) ?? null;
			},
		};
		const held = storeOver(counting);
		for (const version of [2.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
			expect(await refundAt(held, version, at(DAY), at(DAY + MIN)), String(version)).toEqual({
				ok: false,
			});
		}
		const INVALID = new Date(Number.NaN);
		await expect(refundAt(held, 2, at(DAY), INVALID)).rejects.toThrow(RangeError);
		await expect(refundAt(held, 2, INVALID, at(DAY))).rejects.toThrow(RangeError);
		expect(sent).toBe(0);
	});
});
