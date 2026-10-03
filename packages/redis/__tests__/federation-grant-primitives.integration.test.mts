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

// The indivisible steps the Redis federation grant store is built from (ADR
// 2026-09-17-federation-grants-offline-delegation, D16), against a real Redis:
// what one script does, what it refuses, what a key's own deadline becomes,
// and what the subject index holds. The shared contract suite cannot see a
// key TTL, a member's score, or two writers interleaving inside one
// millisecond.

import { Redis } from "ioredis";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type {
	FederationGrantStoreClient,
	RefundFederationGrantRotationInput,
	TakeFederationGrantRotationInput,
} from "#/clients.mjs";
import { makeIoredisFederationGrantStoreClient } from "#/ioredis.mjs";
import { testRedis } from "./support/redis.mjs";

let redis: Redis;
let client: FederationGrantStoreClient;
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	redis = new Redis(at);
	client = makeIoredisFederationGrantStoreClient(redis);
});

afterAll(async () => {
	await redis?.quit();
});

const MIN = 60_000;
const DAY = 86_400_000;
const RETENTION = 30 * DAY;
/** Every case in its own keyspace: the suite's files run in parallel inside one package. */
let prefix = "";
let now = 0;
const at = (ms: number): number => now + ms;

beforeEach(() => {
	run += 1;
	prefix = `t${run}:`;
	now = Math.floor(Date.now() / 1000) * 1000 + 137;
});

const grantKey = (id: string): string => `${prefix}{${id}}:grant`;
const credKey = (id: string): string => `${prefix}{${id}}:cred`;
const indexKey = (subject: string): string => `${prefix}sub:${subject}`;

const base = (id: string): string =>
	JSON.stringify([id, "u-1", "agent", "okta-calendar", String(now)]);

const pending = (
	id = "g-1",
	over: Partial<Parameters<FederationGrantStoreClient["createPending"]>[2]> = {},
) =>
	client.createPending(grantKey(id), credKey(id), {
		nowMs: now,
		base: base(id),
		handle: JSON.stringify(`h-${id}`),
		intentExpiresAtMs: at(10 * MIN),
		retentionMs: RETENTION,
		...over,
	});

/**
 * An `active` record, written field by field rather than through the
 * transitions; what `touch` does to one is a rule of its own.
 */
const active = async (id = "g-1"): Promise<void> => {
	await redis.hset(grantKey(id), {
		format: "1",
		base: base(id),
		status: "active",
		version: "2",
		retentionMs: String(RETENTION),
		expiresAtMs: String(at(30 * DAY)),
	});
};

/** The canonical authorization text, as the codec produces it — opaque to every script. */
const authorization = (tag = "first"): string =>
	JSON.stringify([
		"identity-1",
		`authorization-${tag}`,
		"https://dev-1.okta.test",
		"00u-alice",
		[],
		["openid", "offline_access"],
		String(at(MIN)),
		`sid-${tag}`,
		["openid", "offline_access"],
		String(at(2 * MIN)),
		String(at(30 * DAY)),
	]);

/** A grant taken from `pending` to `active` with a credential: version 2. */
const activeWithCredential = async (id = "g-1"): Promise<void> => {
	await client.createPending(grantKey(id), credKey(id), {
		nowMs: now,
		base: base(id),
		handle: JSON.stringify(`h-${id}`),
		intentExpiresAtMs: at(10 * MIN),
		retentionMs: RETENTION,
	});
	await client.activate(grantKey(id), credKey(id), {
		nowMs: at(2 * MIN),
		handle: JSON.stringify(`h-${id}`),
		authorization: authorization(),
		expiresAtMs: at(30 * DAY),
		identityRevision: "identity-1",
		upstreamIssuer: "https://dev-1.okta.test",
		upstreamSubject: "00u-alice",
		credential: "v2.sealed-1",
	});
};

/** What a key's own deadline is, in epoch milliseconds; -1 when it has none. */
const deadline = async (key: string): Promise<number> =>
	Number(await redis.call("PEXPIRETIME", key));

describe("createPending", () => {
	it("writes the record, at version 1, and hangs the key's deadline on the intent's expiry", async () => {
		const fields = await pending();
		expect(fields).toMatchObject({
			format: "1",
			base: base("g-1"),
			status: "pending",
			version: "1",
			retentionMs: String(RETENTION),
			intentHandle: JSON.stringify("h-g-1"),
			intentExpiresAt: String(at(10 * MIN)),
		});
		// A `pending` record keeps no retention: it is gone when its intent is.
		expect(await deadline(grantKey("g-1"))).toBe(at(10 * MIN));
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});

	it("creates nothing over a record that is still there, whatever this caller's clock says", async () => {
		await pending();
		// A second lodging under the same ID, from a caller whose clock is ahead
		// of the record's horizon: an ID is taken for as long as its record is
		// resident, not for as long as this caller can see it.
		expect(
			await pending("g-1", { nowMs: at(5_000 * DAY), intentExpiresAtMs: at(5_001 * DAY) }),
		).toBeNull();
		const fields = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(fields?.fields.intentExpiresAt).toBe(String(at(10 * MIN)));
	});

	it("creates nothing for an intent that has already lapsed, and nothing for one dated at this instant", async () => {
		for (const intentExpiresAtMs of [now, now - 1, Number.NaN]) {
			expect(await pending("g-1", { intentExpiresAtMs }), String(intentExpiresAtMs)).toBeNull();
		}
		expect(await redis.exists(grantKey("g-1"))).toBe(0);
	});

	it("takes an orphaned credential with it: a fresh record holds no secret from whatever was there before", async () => {
		// A mismatched restore, or a reused ID, can leave a ciphertext behind. It
		// would never authenticate under the new authorization, but a secret at
		// rest that nothing can use is still a secret at rest.
		await redis.set(credKey("g-1"), "v2.stale");
		expect(await pending()).not.toBeNull();
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});

	it("leaves an existing record's credential alone when it refuses", async () => {
		await pending();
		await redis.set(credKey("g-1"), "v2.live");
		expect(await pending("g-1", { handle: JSON.stringify("h-other") })).toBeNull();
		expect(await redis.get(credKey("g-1"))).toBe("v2.live");
	});
});

describe("snapshot", () => {
	it("reads the record and its credential in one step", async () => {
		await pending();
		await redis.set(credKey("g-1"), "v2.sealed");
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.status).toBe("pending");
		expect(snapshot?.credential).toBe("v2.sealed");
	});

	it("says there is no record rather than an empty one, and tells a missing credential from an empty one", async () => {
		expect(await client.snapshot(grantKey("nothing"), credKey("nothing"))).toBeNull();
		await pending();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.credential).toBeNull();
		await redis.set(credKey("g-1"), "");
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.credential).toBe("");
	});

	it("reads nothing at all when the key holds something that is not a record", async () => {
		await redis.set(grantKey("wrong"), "not a hash");
		await expect(client.snapshot(grantKey("wrong"), credKey("wrong"))).rejects.toThrow();
	});
});

describe("the intent pointer", () => {
	it("is replaced on an authorized record and on nothing else, and moves no deadline", async () => {
		await pending();
		// A `pending` grant's intent is named at creation and never renamed: the
		// port refuses a renewal for one that was never authorized.
		expect(
			await client.nameIntent(grantKey("g-1"), {
				nowMs: at(MIN),
				handle: JSON.stringify("h-re"),
				intentExpiresAtMs: at(20 * MIN),
			}),
		).toBeNull();
		expect(await deadline(grantKey("g-1"))).toBe(at(10 * MIN));
	});

	it("is removed by retiring it, and only when the handle given is the one there", async () => {
		await pending();
		expect(
			await client.retireIntent(grantKey("g-1"), {
				nowMs: at(MIN),
				handle: JSON.stringify("h-other"),
			}),
		).toBeNull();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.intentHandle).toBe(
			JSON.stringify("h-g-1"),
		);
	});
});

describe("the intent pointer of an authorized grant", () => {
	it("is retired only by the handle it holds: a consent refused for a superseded intent does not end the newer one", async () => {
		await activeWithCredential();
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		expect(
			await client.retireIntent(grantKey("g-1"), {
				nowMs: at(DAY + MIN),
				handle: JSON.stringify("h-superseded"),
			}),
		).toBeNull();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.intentHandle).toBe(
			JSON.stringify("h-re"),
		);
		// Without a handle, whichever is current — a subject-wide revocation ends
		// every renewal in flight (ADR
		// 2026-09-17-federation-grants-offline-delegation, D13).
		const retired = await client.retireIntent(grantKey("g-1"), { nowMs: at(DAY + MIN) });
		expect(retired?.intentHandle).toBeUndefined();
	});

	it("cannot be activated once it has lapsed, even with the right handle", async () => {
		await activeWithCredential();
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		expect(
			await client.activate(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY + 11 * MIN),
				handle: JSON.stringify("h-re"),
				authorization: authorization("renewed"),
				expiresAtMs: at(60 * DAY),
				identityRevision: "identity-1",
				upstreamIssuer: "https://dev-1.okta.test",
				upstreamSubject: "00u-alice",
				credential: "v2.sealed-2",
			}),
		).toBeNull();
		// A code exchanged for an intent that has lapsed leaves a refresh token
		// at the upstream that nothing will use; the record is untouched.
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.version).toBe("2");
		expect(snapshot?.credential).toBe("v2.sealed-1");
	});
});

describe("touch", () => {
	it("moves the last use forward and never back", async () => {
		await active();
		await client.touch(grantKey("g-1"), at(MIN));
		await client.touch(grantKey("g-1"), at(MIN - 1));
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.lastUsedAt).toBe(
			String(at(MIN)),
		);
	});

	it("records nothing on a grant that is not active: a use is a fact about a grant in use", async () => {
		await pending();
		await client.touch(grantKey("g-1"), at(MIN));
		expect(
			(await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.lastUsedAt,
		).toBeUndefined();
	});

	it("writes nothing when there is no record: an ID that has lapsed is not brought back by a use", async () => {
		await client.touch(grantKey("gone"), at(MIN));
		expect(await redis.exists(grantKey("gone"))).toBe(0);
	});
});

describe("the subject index", () => {
	const member = (id: string): string => JSON.stringify(id);

	it("holds each grant at its horizon, and the key's own deadline runs past the last of them", async () => {
		await client.reserve(indexKey("u-1"), member("g-1"), at(30 * DAY), MIN);
		await client.reserve(indexKey("u-1"), member("g-2"), at(60 * DAY), MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1"), member("g-2")]);
		expect(await deadline(indexKey("u-1"))).toBe(at(60 * DAY) + MIN);
	});

	it("moves a horizon forward and never back: the record that wins a race is the one still listed", async () => {
		// Two writers lodge the same ID. The one whose record is created is not
		// necessarily the one that reserved last, so a reservation that loses must
		// not pull the horizon back under the winner.
		await client.reserve(indexKey("u-1"), member("g-1"), at(60 * DAY), MIN);
		await client.reserve(indexKey("u-1"), member("g-1"), at(10 * MIN), MIN);
		expect(await redis.zscore(indexKey("u-1"), member("g-1"))).toBe(String(at(60 * DAY)));
		expect(await deadline(indexKey("u-1"))).toBe(at(60 * DAY) + MIN);
	});

	it("drops a member only once its horizon is past by the allowance, and never one still to come", async () => {
		await client.reserve(indexKey("u-1"), member("due"), at(MIN), MIN);
		await client.reserve(indexKey("u-1"), member("just-due"), at(2 * MIN), MIN);
		await client.reserve(indexKey("u-1"), member("to-come"), at(10 * MIN), MIN);
		await client.prune(indexKey("u-1"), at(3 * MIN), MIN);
		// `just-due` sits exactly at the allowance and stays: the boundary belongs
		// to the record, because a member dropped while a replica whose clock is
		// behind can still read its record is a record `find` answers for and a
		// listing has lost.
		expect(await client.members(indexKey("u-1"))).toStrictEqual([
			member("just-due"),
			member("to-come"),
		]);
	});

	it("is gone as a whole once every horizon it holds is past: an index of dead members is not kept alive", async () => {
		// The deadline is the last horizon plus the allowance, so an index with
		// nothing live in it has a deadline behind Redis's own clock, and Redis
		// takes it from there. Nothing had to decide to delete it.
		await client.reserve(indexKey("u-1"), member("long-gone"), at(-DAY), MIN);
		expect(await redis.exists(indexKey("u-1"))).toBe(0);
	});

	it("never drops a member reserved for a record still being written: its horizon is in the future", async () => {
		// The window the layout is built around. The member goes in first, at the
		// horizon the record will have, so a pruning listing in between sees a
		// score that is not due and leaves it alone.
		await client.reserve(indexKey("u-1"), member("g-1"), at(10 * MIN), MIN);
		await client.prune(indexKey("u-1"), now, MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1")]);
		expect(await pending()).not.toBeNull();
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1")]);
	});

	it("is gone when the last of its members is, and not before", async () => {
		await client.reserve(indexKey("u-1"), member("g-1"), at(MIN), MIN);
		expect(await redis.exists(indexKey("u-1"))).toBe(1);
		await client.prune(indexKey("u-1"), at(30 * MIN), MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([]);
		expect(await redis.exists(indexKey("u-1"))).toBe(0);
	});

	it("says nothing is there for a subject that never had a grant", async () => {
		expect(await client.members(indexKey("u-nobody"))).toStrictEqual([]);
		await client.prune(indexKey("u-nobody"), now, MIN);
		expect(await redis.exists(indexKey("u-nobody"))).toBe(0);
	});
});

describe("activate", () => {
	it("replaces the authorization whole, seals the credential, retires the intent and bumps the version", async () => {
		await pending();
		const fields = await client.activate(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(2 * MIN),
			handle: JSON.stringify("h-g-1"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-1",
		});
		expect(fields).toMatchObject({
			status: "active",
			version: "2",
			authorization: authorization(),
			expiresAtMs: String(at(30 * DAY)),
		});
		expect(fields?.intentHandle).toBeUndefined();
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
		// The record now runs from its expiry plus the retention; the credential
		// gets no retention of its own.
		expect(await deadline(grantKey("g-1"))).toBe(at(30 * DAY) + RETENTION);
		expect(await deadline(credKey("g-1"))).toBe(at(30 * DAY));
	});

	it("refuses a handle that is not the current intent, and a lapsed one, leaving the grant exactly as it was", async () => {
		await pending();
		for (const over of [{ handle: JSON.stringify("h-other") }, { nowMs: at(11 * MIN) }]) {
			expect(
				await client.activate(grantKey("g-1"), credKey("g-1"), {
					nowMs: at(2 * MIN),
					handle: JSON.stringify("h-g-1"),
					authorization: authorization(),
					expiresAtMs: at(30 * DAY),
					identityRevision: "identity-1",
					upstreamIssuer: "https://dev-1.okta.test",
					upstreamSubject: "00u-alice",
					credential: "v2.sealed-1",
					...over,
				}),
				JSON.stringify(over),
			).toBeNull();
		}
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.status).toBe("pending");
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});

	it("refuses a renewal that re-points the grant: the same upstream account and the same identity, or nothing", async () => {
		await pending();
		await client.activate(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(2 * MIN),
			handle: JSON.stringify("h-g-1"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-1",
		});
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		for (const over of [
			{ identityRevision: "identity-2" },
			{ upstreamIssuer: "https://other.okta.test" },
			{ upstreamSubject: "00u-bob" },
		]) {
			expect(
				await client.activate(grantKey("g-1"), credKey("g-1"), {
					nowMs: at(DAY + MIN),
					handle: JSON.stringify("h-re"),
					authorization: authorization("renewed"),
					expiresAtMs: at(60 * DAY),
					identityRevision: "identity-1",
					upstreamIssuer: "https://dev-1.okta.test",
					upstreamSubject: "00u-alice",
					credential: "v2.sealed-2",
					...over,
				}),
				JSON.stringify(over),
			).toBeNull();
		}
		// Still the first authorization, still its credential, still version 2.
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.version).toBe("2");
		expect(snapshot?.credential).toBe("v2.sealed-1");
	});

	it("keeps a use recorded before it, and drops the marker and the stamp with the authorization", async () => {
		await activeWithCredential();
		await client.touch(grantKey("g-1"), at(MIN));
		await redis.hset(grantKey("g-1"), {
			ineligible: JSON.stringify(["lifetime_over_maximum", String(at(MIN)), "1800"]),
			failureAt: String(at(MIN)),
			failureKind: "unavailable",
			failureCount: "2",
		});
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		const fields = await client.activate(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY + MIN),
			handle: JSON.stringify("h-re"),
			authorization: authorization("renewed"),
			expiresAtMs: at(60 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-2",
		});
		expect(fields?.lastUsedAt).toBe(String(at(MIN)));
		expect(fields?.ineligible).toBeUndefined();
		expect(fields?.failureAt).toBeUndefined();
		expect(fields?.failureCount).toBeUndefined();
		expect(await deadline(grantKey("g-1"))).toBe(at(60 * DAY) + RETENTION);
	});
});

describe("replaceCredentials", () => {
	it("replaces the credential, replaces the marker whole, forgets the stamp and bumps the version", async () => {
		await activeWithCredential();
		await redis.hset(grantKey("g-1"), {
			failureAt: String(at(MIN)),
			failureKind: "unavailable",
			failureCount: "3",
		});
		const fields = await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 2,
			credential: "v2.sealed-2",
			ineligible: JSON.stringify(["no_finite_lifetime", String(at(DAY)), "0"]),
		});
		expect(fields).toMatchObject({
			version: "3",
			ineligible: JSON.stringify(["no_finite_lifetime", String(at(DAY)), "0"]),
		});
		expect(fields?.failureAt).toBeUndefined();
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-2");
		// The credential's deadline is the authorization's expiry again, and not
		// a lifetime of its own: a refresh moves no horizon.
		expect(await deadline(credKey("g-1"))).toBe(at(30 * DAY));
		expect(await deadline(grantKey("g-1"))).toBe(at(30 * DAY) + RETENTION);
	});

	it("removes a marker the refresh cleared", async () => {
		await activeWithCredential();
		await redis.hset(grantKey("g-1"), {
			ineligible: JSON.stringify(["no_finite_lifetime", String(at(MIN)), "0"]),
		});
		const fields = await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 2,
			credential: "v2.sealed-2",
			ineligible: null,
		});
		expect(fields?.ineligible).toBeUndefined();
	});

	it("refuses a version that is not the one stored, and writes nothing", async () => {
		await activeWithCredential();
		for (const expectedVersion of [1, 3, 0, -1, Number.NaN, 2.5]) {
			expect(
				await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
					nowMs: at(DAY),
					expectedVersion,
					credential: "v2.wrong",
					ineligible: null,
				}),
				String(expectedVersion),
			).toBeNull();
		}
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
	});

	it("refuses once the stored expiry has passed, however long the record is still retained", async () => {
		await activeWithCredential();
		expect(
			await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(30 * DAY),
				expectedVersion: 2,
				credential: "v2.wrong",
				ineligible: null,
			}),
		).toBeNull();
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
	});

	it("refuses to replace a credential that is not there, in the same step as the write", async () => {
		// The credential key's deadline is the expiry on the server's clock; once
		// it has fired, a refresh whose caller's clock is still before the expiry
		// finds nothing to rotate. The adapter reads the credential a round trip
		// before the script, and the deadline can fire in between — so the
		// script checks again, and neither bumps the version nor writes a
		// credential that would take the same past deadline and be gone at once.
		await activeWithCredential();
		await redis.del(credKey("g-1"));
		expect(
			await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY),
				expectedVersion: 2,
				credential: "v2.sealed-2",
				ineligible: null,
			}),
		).toBeNull();
		expect(await redis.hget(grantKey("g-1"), "version")).toBe("2");
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});
});

describe("requireReauthorization", () => {
	it("takes the credential, keeps the marker, forgets the stamp and bumps the version", async () => {
		await activeWithCredential();
		await redis.hset(grantKey("g-1"), {
			ineligible: JSON.stringify(["no_finite_lifetime", String(at(MIN)), "0"]),
			failureAt: String(at(MIN)),
			failureKind: "rejected",
			failureCount: "1",
		});
		const fields = await client.requireReauthorization(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 2,
		});
		expect(fields).toMatchObject({ status: "reauthorization_required", version: "3" });
		expect(fields?.ineligible).toBe(JSON.stringify(["no_finite_lifetime", String(at(MIN)), "0"]));
		expect(fields?.failureAt).toBeUndefined();
		expect(await redis.exists(credKey("g-1"))).toBe(0);
		// The horizon does not move: what the user consented to has not changed.
		expect(await deadline(grantKey("g-1"))).toBe(at(30 * DAY) + RETENTION);
	});

	it("is taken even past the stored expiry: an upstream that says the credential is dead is believed whenever it says it", async () => {
		await activeWithCredential();
		const fields = await client.requireReauthorization(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(40 * DAY),
			expectedVersion: 2,
		});
		expect(fields?.status).toBe("reauthorization_required");
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});
});

describe("revoke", () => {
	it("ends the grant, takes the credential and the intent, and keeps what it was authorized for", async () => {
		await activeWithCredential();
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		const fields = await client.revoke(grantKey("g-1"), credKey("g-1"), {
			atMs: at(2 * DAY),
			by: "client",
		});
		expect(fields).toMatchObject({
			status: "revoked",
			version: "3",
			revokedBy: "client",
			revokedAt: String(at(2 * DAY)),
			authorization: authorization(),
		});
		expect(fields?.intentHandle).toBeUndefined();
		expect(await redis.exists(credKey("g-1"))).toBe(0);
		// A revocation moves no horizon: an authorized grant is retained from its
		// expiry whenever it was revoked.
		expect(await deadline(grantKey("g-1"))).toBe(at(30 * DAY) + RETENTION);
	});

	it("retains a grant revoked before it was ever authorized from the revocation, since it has no expiry", async () => {
		await pending();
		const fields = await client.revoke(grantKey("g-1"), credKey("g-1"), {
			atMs: at(MIN),
			by: "subject",
		});
		expect(fields).toMatchObject({ status: "revoked", version: "2", revokedAt: String(at(MIN)) });
		expect(await deadline(grantKey("g-1"))).toBe(at(MIN) + RETENTION);
	});

	it("is recorded once: the first revocation stays as it was recorded", async () => {
		await activeWithCredential();
		await client.revoke(grantKey("g-1"), credKey("g-1"), { atMs: at(DAY), by: "client" });
		expect(
			await client.revoke(grantKey("g-1"), credKey("g-1"), { atMs: at(2 * DAY), by: "operator" }),
		).toBeNull();
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.revokedBy).toBe("client");
		expect(snapshot?.fields.revokedAt).toBe(String(at(DAY)));
	});
});

describe("the credential's extension", () => {
	const activate = (extension?: string) =>
		client.activate(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(2 * MIN),
			handle: JSON.stringify("h-g-1"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-1",
			...(extension === undefined ? {} : { extension }),
		});
	const replace = (expectedVersion: number, extension?: string) =>
		client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion,
			credential: "v2.sealed-2",
			ineligible: null,
			...(extension === undefined ? {} : { extension }),
		});

	it("is written by activate in the step that writes the credential, and taken away when none is given", async () => {
		await pending();
		await redis.hset(grantKey("g-1"), "ext", "left-over");
		const fields = await activate("v2.ext-1");
		expect(fields?.ext).toBe("v2.ext-1");
		expect(await redis.hget(grantKey("g-1"), "ext")).toBe("v2.ext-1");

		await pending("g-2");
		await redis.hset(grantKey("g-2"), "ext", "left-over");
		const plain = await client.activate(grantKey("g-2"), credKey("g-2"), {
			nowMs: at(2 * MIN),
			handle: JSON.stringify("h-g-2"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-1",
		});
		expect(plain?.status).toBe("active");
		expect(plain?.ext).toBeUndefined();
		expect(await redis.hexists(grantKey("g-2"), "ext")).toBe(0);
	});

	it("is replaced with the credential, and taken away when the new credential has none", async () => {
		await pending();
		await activate("v2.ext-1");
		expect((await replace(2, "v2.ext-2"))?.ext).toBe("v2.ext-2");
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-2");

		const fields = await replace(3);
		expect(fields?.version).toBe("4");
		expect(fields?.ext).toBeUndefined();
		expect(await redis.hexists(grantKey("g-1"), "ext")).toBe(0);
	});

	it("is left exactly as it was by a refused activation or replacement", async () => {
		await pending();
		await activate("v2.ext-1");
		const refused = await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 7,
			credential: "v2.sealed-2",
			ineligible: null,
			extension: "v2.ext-2",
		});
		expect(refused).toBeNull();
		expect(await redis.hget(grantKey("g-1"), "ext")).toBe("v2.ext-1");
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
	});

	it("goes with the credential when the user is asked again, and when the grant is revoked", async () => {
		await pending();
		await activate("v2.ext-1");
		await client.requireReauthorization(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 2,
		});
		expect(await redis.hexists(grantKey("g-1"), "ext")).toBe(0);

		await pending("g-2");
		await client.activate(grantKey("g-2"), credKey("g-2"), {
			nowMs: at(2 * MIN),
			handle: JSON.stringify("h-g-2"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-1",
			extension: "v2.ext-1",
		});
		await client.revoke(grantKey("g-2"), credKey("g-2"), { atMs: at(DAY), by: "client" });
		expect(await redis.hexists(grantKey("g-2"), "ext")).toBe(0);
	});

	it("is read in the same snapshot as the record and the credential", async () => {
		await pending();
		await activate("v2.ext-1");
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.ext).toBe("v2.ext-1");
		expect(snapshot?.credential).toBe("v2.sealed-1");
	});
});

describe("noteRefreshFailure", () => {
	const stamp = (over: Record<string, unknown> = {}) =>
		client.noteRefreshFailure(grantKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion: 2,
			atMs: at(DAY),
			kind: "unavailable",
			rowMs: 300_000,
			retryAfterSeconds: undefined,
			upstreamCode: undefined,
			...over,
		});

	it("counts from one, bumps no version, and touches nothing else", async () => {
		await activeWithCredential();
		const fields = await stamp();
		expect(fields).toMatchObject({
			version: "2",
			failureAt: String(at(DAY)),
			failureKind: "unavailable",
			failureCount: "1",
		});
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
	});

	it("counts on while the stamps are in a row, and starts again once they are not", async () => {
		await activeWithCredential();
		await stamp();
		expect((await stamp({ atMs: at(DAY + 300_000) }))?.failureCount).toBe("2");
		expect((await stamp({ atMs: at(DAY + 600_000) }))?.failureCount).toBe("3");
		expect((await stamp({ atMs: at(DAY + 900_001), nowMs: at(DAY + 900_001) }))?.failureCount).toBe(
			"1",
		);
	});

	it("counts an equal instant onward, and is never dated back", async () => {
		await activeWithCredential();
		await stamp({ atMs: at(DAY) });
		expect((await stamp({ atMs: at(DAY) }))?.failureCount).toBe("2");
		expect(await stamp({ atMs: at(DAY) - 1 })).toBeNull();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.failureAt).toBe(
			String(at(DAY)),
		);
	});

	it("measures the row from the failure, and not from the clock of whoever reported it", async () => {
		// A stamp that took ten minutes to arrive is still one failure after the
		// last: the row is the distance between the two FAILURES. Measured from
		// the caller's clock instead, a slow report would start the count again
		// and the backoff a run of failures earns would never be reached (ADR
		// 2026-09-17-federation-grants-offline-delegation, D12).
		await activeWithCredential();
		await stamp({ atMs: at(DAY) });
		const late = await stamp({ atMs: at(DAY + 1_000), nowMs: at(DAY + 600_000) });
		expect(late?.failureCount).toBe("2");
	});

	it("replaces the whole stamp: what the new one does not carry is gone", async () => {
		await activeWithCredential();
		await stamp({ kind: "rate_limited", retryAfterSeconds: 120, upstreamCode: "slow_down" });
		const fields = await stamp({ atMs: at(DAY + 1_000) });
		expect(fields?.failureKind).toBe("unavailable");
		expect(fields?.failureRetryAfterSeconds).toBeUndefined();
		expect(fields?.failureUpstreamCode).toBeUndefined();
	});

	it("refuses a stale version: a failure that outlived its refresh must not land on a newer credential", async () => {
		await activeWithCredential();
		await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(MIN),
			expectedVersion: 2,
			credential: "v2.sealed-2",
			ineligible: null,
		});
		expect(await stamp()).toBeNull();
		expect(
			(await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.failureAt,
		).toBeUndefined();
	});

	it("refuses once the stored expiry has passed", async () => {
		await activeWithCredential();
		expect(await stamp({ nowMs: at(30 * DAY), atMs: at(30 * DAY) })).toBeNull();
	});
});

describe("takeRotation", () => {
	const HOUR = 3_600_000;
	const take = (over: Partial<TakeFederationGrantRotationInput> = {}, id = "g-1") => {
		if (client.takeRotation === undefined)
			throw new Error("fixture: the client has no takeRotation");
		return client.takeRotation(grantKey(id), {
			nowMs: at(DAY),
			expectedVersion: 2,
			limit: 2,
			windowMs: HOUR,
			...over,
		});
	};
	const fieldsOf = async (id = "g-1") => (await client.snapshot(grantKey(id), credKey(id)))?.fields;

	it("opens a window with the first take, bumps the version once, and touches nothing else", async () => {
		await activeWithCredential();
		const before = await redis.hgetall(grantKey("g-1"));
		const fields = await take();
		expect(fields).toStrictEqual({
			...before,
			version: "3",
			rotationsSince: String(at(DAY)),
			rotationsCount: "1",
		});
		expect(await redis.get(credKey("g-1"))).toBe("v2.sealed-1");
		expect(await deadline(grantKey("g-1"))).toBe(at(30 * DAY) + RETENTION);
	});

	it("counts on within the window up to the limit, then refuses and writes nothing", async () => {
		await activeWithCredential();
		await take();
		expect(await take({ nowMs: at(DAY + MIN), expectedVersion: 3 })).toMatchObject({
			version: "4",
			rotationsSince: String(at(DAY)),
			rotationsCount: "2",
		});
		const before = await redis.hgetall(grantKey("g-1"));
		expect(await take({ nowMs: at(DAY + 2 * MIN), expectedVersion: 4 })).toBeNull();
		expect(await redis.hgetall(grantKey("g-1"))).toStrictEqual(before);
	});

	it("opens a new window from since + windowMs on, and not a millisecond before", async () => {
		await activeWithCredential();
		await take({ limit: 1 });
		expect(await take({ limit: 1, nowMs: at(DAY + HOUR - 1), expectedVersion: 3 })).toBeNull();
		expect(await take({ limit: 1, nowMs: at(DAY + HOUR), expectedVersion: 3 })).toMatchObject({
			rotationsSince: String(at(DAY + HOUR)),
			rotationsCount: "1",
		});
	});

	it("refuses a stale version, a time past the stored expiry, and a grant that is not active", async () => {
		await activeWithCredential();
		expect(await take({ expectedVersion: 3 })).toBeNull();
		expect(await take({ nowMs: at(30 * DAY) })).toBeNull();
		await pending("g-p");
		expect(await take({ expectedVersion: 1, nowMs: at(MIN) }, "g-p")).toBeNull();
		await activeWithCredential("g-r");
		await client.requireReauthorization(grantKey("g-r"), credKey("g-r"), {
			nowMs: at(MIN),
			expectedVersion: 2,
		});
		expect(await take({ expectedVersion: 3 }, "g-r")).toBeNull();
		expect(await take({}, "g-none")).toBeNull();
		for (const id of ["g-1", "g-p", "g-r"]) {
			expect((await fieldsOf(id))?.rotationsSince, id).toBeUndefined();
		}
		expect(await redis.exists(grantKey("g-none"))).toBe(0);
	});

	it("refuses a bound it cannot count with, in the script as well, and writes nothing", async () => {
		await activeWithCredential();
		for (const over of [
			{ limit: 0 },
			{ limit: -1 },
			{ limit: Number.NaN },
			{ windowMs: 0 },
			{ windowMs: -1 },
			{ windowMs: Number.NaN },
			{ windowMs: Number.POSITIVE_INFINITY },
		]) {
			expect(await take(over), JSON.stringify(over)).toBeNull();
		}
		expect((await fieldsOf())?.rotationsSince).toBeUndefined();
	});

	it("reads a window it cannot parse as none, and opens a new one over it", async () => {
		await activeWithCredential();
		let version = 2;
		for (const [since, count] of [
			[String(at(DAY)), "1e0"],
			[String(at(DAY)), "-1"],
			[`${at(DAY)}.5`, "1"],
			[String(at(DAY)), undefined],
		] as const) {
			await redis.hdel(grantKey("g-1"), "rotationsSince", "rotationsCount");
			await redis.hset(grantKey("g-1"), {
				rotationsSince: since,
				...(count === undefined ? {} : { rotationsCount: count }),
			});
			expect(
				await take({ nowMs: at(DAY + MIN), limit: 1, expectedVersion: version }),
				`${since} ${count}`,
			).toMatchObject({
				rotationsSince: String(at(DAY + MIN)),
				rotationsCount: "1",
			});
			version += 1;
		}
	});

	it("is kept by every write but an activation, which clears it", async () => {
		await activeWithCredential();
		await take();
		const kept = { rotationsSince: String(at(DAY)), rotationsCount: "1" };
		await client.touch(grantKey("g-1"), at(DAY + MIN));
		await client.noteRefreshFailure(grantKey("g-1"), {
			nowMs: at(DAY + MIN),
			expectedVersion: 3,
			atMs: at(DAY + MIN),
			kind: "unavailable",
			rowMs: 300_000,
			retryAfterSeconds: undefined,
			upstreamCode: undefined,
		});
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY + MIN),
			handle: JSON.stringify("h-re"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		await client.retireIntent(grantKey("g-1"), { nowMs: at(DAY + MIN) });
		expect(
			await client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY + MIN),
				expectedVersion: 3,
				credential: "v2.sealed-2",
				ineligible: null,
			}),
		).toMatchObject({ version: "4", ...kept });
		expect(
			await client.requireReauthorization(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY + MIN),
				expectedVersion: 4,
			}),
		).toMatchObject({ status: "reauthorization_required", ...kept });
		await client.nameIntent(grantKey("g-1"), {
			nowMs: at(DAY + MIN),
			handle: JSON.stringify("h-renew"),
			intentExpiresAtMs: at(DAY + 10 * MIN),
		});
		const renewed = await client.activate(grantKey("g-1"), credKey("g-1"), {
			nowMs: at(DAY + 2 * MIN),
			handle: JSON.stringify("h-renew"),
			authorization: authorization(),
			expiresAtMs: at(30 * DAY),
			identityRevision: "identity-1",
			upstreamIssuer: "https://dev-1.okta.test",
			upstreamSubject: "00u-alice",
			credential: "v2.sealed-3",
		});
		expect(renewed?.status).toBe("active");
		expect(renewed?.rotationsSince).toBeUndefined();
		expect(renewed?.rotationsCount).toBeUndefined();
	});

	it("is kept by a revocation, which keeps what the grant was", async () => {
		await activeWithCredential();
		await take();
		expect(
			await client.revoke(grantKey("g-1"), credKey("g-1"), { atMs: at(DAY + MIN), by: "client" }),
		).toMatchObject({ status: "revoked", rotationsSince: String(at(DAY)), rotationsCount: "1" });
	});
});

describe("refundRotation", () => {
	const refund = (over: Partial<RefundFederationGrantRotationInput> = {}, id = "g-1") => {
		if (client.refundRotation === undefined)
			throw new Error("fixture: the client has no refundRotation");
		return client.refundRotation(grantKey(id), {
			nowMs: at(DAY + MIN),
			expectedVersion: 2,
			sinceMs: at(DAY),
			...over,
		});
	};
	const rawOf = (id = "g-1") => redis.hgetall(grantKey(id));

	it("reads a window opened outside the Date range as none, as the take does, and writes nothing", async () => {
		await activeWithCredential();
		const since = 9_000_000_000_000_000;
		await redis.hset(grantKey("g-1"), { rotationsSince: String(since), rotationsCount: "1" });
		const before = await rawOf();
		expect(await refund({ sinceMs: since })).toBeNull();
		expect(await rawOf()).toEqual(before);
	});

	it("refuses a stored version whose successor is not a safe integer, and writes nothing", async () => {
		// 2^53 a bump could not move; the largest safe integer it would move to
		// a version no reader accepts.
		for (const version of [2 ** 53, Number.MAX_SAFE_INTEGER]) {
			await activeWithCredential();
			await redis.hset(grantKey("g-1"), {
				version: String(version),
				rotationsSince: String(at(DAY)),
				rotationsCount: "2",
			});
			const before = await rawOf();
			expect(await refund({ expectedVersion: version }), String(version)).toBeNull();
			expect(await refund({ expectedVersion: version }), String(version)).toBeNull();
			expect(await rawOf(), String(version)).toEqual(before);
			await redis.del(grantKey("g-1"), credKey("g-1"));
		}
	});
});

describe("the stored version, as every script reads it", () => {
	const MAX = Number.MAX_SAFE_INTEGER;
	const rawOf = (id = "g-1") => redis.hgetall(grantKey(id));
	/** A stored version the TypeScript reader does not read as a safe integer, though Lua's tonumber does. */
	const LOOSE = ["2.0", "0x2", " 2", "2e0", "+2"];
	const activateInput = () => ({
		nowMs: at(2 * MIN),
		handle: JSON.stringify("h-g-1"),
		authorization: authorization(),
		expiresAtMs: at(30 * DAY),
		identityRevision: "identity-1",
		upstreamIssuer: "https://dev-1.okta.test",
		upstreamSubject: "00u-alice",
		credential: "v2.sealed-2",
	});
	const take = (expectedVersion: number) => {
		if (client.takeRotation === undefined)
			throw new Error("fixture: the client has no takeRotation");
		return client.takeRotation(grantKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion,
			limit: 2,
			windowMs: 3_600_000,
		});
	};
	const stamp = (expectedVersion: number) =>
		client.noteRefreshFailure(grantKey("g-1"), {
			nowMs: at(DAY),
			expectedVersion,
			atMs: at(DAY),
			kind: "unavailable",
			rowMs: 300_000,
			retryAfterSeconds: undefined,
			upstreamCode: undefined,
		});
	const guarded = {
		takeRotation: take,
		replaceCredentials: (expectedVersion: number) =>
			client.replaceCredentials(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY),
				expectedVersion,
				credential: "v2.sealed-2",
				ineligible: null,
			}),
		requireReauthorization: (expectedVersion: number) =>
			client.requireReauthorization(grantKey("g-1"), credKey("g-1"), {
				nowMs: at(DAY),
				expectedVersion,
			}),
	};

	it("is refused by every guarded bump at the largest safe integer, whose successor no reader accepts, and nothing is written", async () => {
		for (const [name, write] of Object.entries(guarded)) {
			await activeWithCredential();
			await redis.hset(grantKey("g-1"), "version", String(MAX));
			const before = await rawOf();
			expect(await write(MAX), name).toBeNull();
			expect(await rawOf(), name).toStrictEqual(before);
			expect(await redis.get(credKey("g-1")), name).toBe("v2.sealed-1");
			await redis.del(grantKey("g-1"), credKey("g-1"));
		}
	});

	it("is refused by an activation at the largest safe integer, and by one that does not read as a safe integer, and nothing is written", async () => {
		for (const version of [String(MAX), "2.0"]) {
			await pending();
			await redis.hset(grantKey("g-1"), "version", version);
			const before = await rawOf();
			expect(
				await client.activate(grantKey("g-1"), credKey("g-1"), activateInput()),
				version,
			).toBeNull();
			expect(await rawOf(), version).toStrictEqual(before);
			expect(await redis.exists(credKey("g-1")), version).toBe(0);
			await redis.del(grantKey("g-1"), credKey("g-1"));
		}
	});

	it("does not stop a revocation at the largest safe integer, or at one that does not read as one: the grant ends, its version left as it was", async () => {
		// A revocation has no version to match and always wins: a version it
		// cannot bump to one the reader accepts is not a reason to leave the
		// credential at rest.
		for (const version of [String(MAX), "2.0"]) {
			await activeWithCredential();
			await redis.hset(grantKey("g-1"), "version", version);
			const fields = await client.revoke(grantKey("g-1"), credKey("g-1"), {
				atMs: at(DAY),
				by: "operator",
			});
			expect(fields, version).toMatchObject({ status: "revoked", version });
			expect(await redis.exists(credKey("g-1")), version).toBe(0);
			await redis.del(grantKey("g-1"), credKey("g-1"));
		}
	});

	it("matches the expected version only when it reads as the reader reads it", async () => {
		const compared = { ...guarded, noteRefreshFailure: stamp };
		for (const [name, write] of Object.entries(compared)) {
			for (const version of LOOSE) {
				await activeWithCredential();
				await redis.hset(grantKey("g-1"), "version", version);
				const before = await rawOf();
				expect(await write(2), `${name} ${JSON.stringify(version)}`).toBeNull();
				expect(await rawOf(), `${name} ${JSON.stringify(version)}`).toStrictEqual(before);
				expect(await redis.get(credKey("g-1")), name).toBe("v2.sealed-1");
				await redis.del(grantKey("g-1"), credKey("g-1"));
			}
		}
	});
});

describe("the lock over a real connection", () => {
	const lockKey = (id: string): string => `${prefix}{${id}}:lock`;

	it("is held by one caller at a time, and its TTL is the one asked for", async () => {
		expect(await client.tryLock(lockKey("g-1"), "token-a", 30_000)).toBe(true);
		expect(await client.tryLock(lockKey("g-1"), "token-b", 30_000)).toBe(false);
		const ttl = await redis.pttl(lockKey("g-1"));
		expect(ttl).toBeGreaterThan(29_000);
		expect(ttl).toBeLessThanOrEqual(30_000);
	});

	it("is freed only by the token that holds it: past the TTL the lock is somebody else's", async () => {
		await client.tryLock(lockKey("g-1"), "token-a", 30_000);
		await client.unlock(lockKey("g-1"), "token-b");
		expect(await redis.get(lockKey("g-1"))).toBe("token-a");
		await client.unlock(lockKey("g-1"), "token-a");
		expect(await redis.exists(lockKey("g-1"))).toBe(0);
		// And freeing one that is already gone is not an error.
		await client.unlock(lockKey("g-1"), "token-a");
	});

	it("is a key of its own, and taking it changes no record", async () => {
		await pending();
		await client.tryLock(lockKey("g-1"), "token-a", 30_000);
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.version).toBe("1");
	});
});
