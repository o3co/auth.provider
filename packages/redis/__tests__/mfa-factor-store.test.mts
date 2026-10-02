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
 * The Redis `MfaFactorStore` (ADR 2026-09-25-multi-factor-authentication, D7)
 * against the test kit's two contract suites, the records' and the factor
 * set's conditional writes, on a real Redis, and what is Redis-specific below
 * them: one hash per subject with a field per factor and the set's generation
 * under `~g`, no TTL while the set holds a factor and the tombstone's after it
 * is emptied, a compare-and-set that never decodes the JSON, a stored record
 * this adapter cannot read refused rather than read as no factor (same ADR,
 * D12 and D28), a hash without a generation, the versioned read refused by a
 * replica, and a membership write that reaches the server past its deadline
 * writing nothing.
 *
 * The suites' second instance is a store on a second connection, so the races
 * they set up are races across sockets, as in a deployment.
 */

import {
	BUNDLED_STORE_WRITE_LIFETIME_MS,
	type MfaFactorRecord,
	type MfaFactorStore,
	readConditionalCreateAnswer,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import {
	type MfaFactorStoreHarness,
	mfaFactorStoreConditionalContract,
	mfaFactorStoreContract,
} from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	MFA_FACTOR_CREATE_IF,
	MFA_FACTOR_LIST_VERSIONED,
	MFA_FACTOR_REMOVE_ALL,
	MFA_FACTOR_REMOVE_IF,
} from "#/ioredis/scripts/mfa.mjs";
import { makeIoredisMfaFactorStoreClient } from "#/ioredis.mjs";
import {
	createRedisMfaFactorStore,
	REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS,
} from "#/mfa-factor-store.mjs";
import { EXPIRY_GRACE_MS, serverClock, testRedis, until } from "./support/redis.mjs";

let connections: Redis[] = [];
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	connections = [new Redis(at), new Redis(at)];
});

afterAll(async () => {
	await Promise.all(connections.map((connection) => connection.quit()));
});

const first = (): Redis => connections[0] as Redis;
const second = (): Redis => connections[1] as Redis;

/** How the adapter spells a value inside a key or a field — looked at from outside, as the probes must. */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/** A keyspace of its own for each case. */
const freshPrefix = (): string => {
	run += 1;
	return `mfaf:test-${run}:`;
};

/**
 * The subjects' hashes under `prefix`: every key but the replay keys, each
 * a write's answer kept for a second until its deadline.
 */
const hashesAt = async (prefix: string): Promise<string[]> =>
	(await first().keys(`${prefix}*`)).filter((key) => !key.includes("}:w:"));

/** The subject's hash under `prefix`. */
const keyAt = (prefix: string, subject: string): string => `${prefix}{${keyPart(subject)}}`;

const storeAt = (keyPrefix: string, connection: Redis = first()): MfaFactorStore =>
	createRedisMfaFactorStore({ client: makeIoredisMfaFactorStoreClient(connection), keyPrefix });

/**
 * Expires `subject`'s tombstone at once, as the server's clock passing its
 * retention would: a key with a TTL is given 1 ms of it, and the wait is for
 * the key to be gone. A key without one — a set holding a factor — is left
 * as it is: nothing here judges membership or deletes.
 */
const expireTombstone =
	(prefix: string) =>
	async (subject: string): Promise<void> => {
		const key = keyAt(prefix, subject);
		const shortened = await first().eval(
			"if redis.call('PTTL', KEYS[1]) > 0 then return redis.call('PEXPIRE', KEYS[1], 1) end return 0",
			1,
			key,
		);
		if (shortened !== 1) return;
		await until(
			async () => (await first().exists(key)) === 0,
			"the tombstone to expire",
			Date.now() + EXPIRY_GRACE_MS,
		);
	};

/**
 * A harness over a keyspace of its own: the store on one connection, its
 * second on the other, a store whose connection reaches nothing, and the
 * tombstone's expiry brought forward.
 */
const harness = async (): Promise<MfaFactorStoreHarness> => {
	const prefix = freshPrefix();
	const opened: Redis[] = [];
	return {
		store: storeAt(prefix, first()),
		second: storeAt(prefix, second()),
		unreachable: () => {
			const io = new Redis({
				host: "127.0.0.1",
				port: 1,
				lazyConnect: true,
				enableOfflineQueue: false,
				maxRetriesPerRequest: 0,
				retryStrategy: () => null,
			});
			io.on("error", () => {});
			opened.push(io);
			return storeAt(prefix, io);
		},
		forceExpire: expireTombstone(prefix),
		close: async () => {
			for (const io of opened) io.disconnect();
		},
	};
};

const SUPPORTS = { unreachable: true, forceExpire: true } as const;

describe("MfaFactorStore contract", () => {
	for (const contractCase of mfaFactorStoreContract({ build: harness, supports: SUPPORTS })) {
		it(contractCase.name, contractCase.run);
	}
});

describe("MfaFactorStore conditional-write contract", () => {
	for (const contractCase of mfaFactorStoreConditionalContract({
		build: harness,
		supports: SUPPORTS,
	})) {
		it(contractCase.name, contractCase.run);
	}
});

const RECORD = (overrides: Partial<MfaFactorRecord> = {}): MfaFactorRecord => ({
	id: "factor-1",
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque-sealed-data",
	...overrides,
});

/** Adds `record` to its subject's set at the set's current generation: a conditional create that must land. */
const seed = async (store: MfaFactorStore, record: MfaFactorRecord): Promise<void> => {
	const { generation } = await store.listVersioned(record.subject);
	const answer = readConditionalCreateAnswer(await store.createIf(record, generation));
	if (answer.outcome !== "created") throw new Error(`${record.id} was not seeded`);
};

describe("createRedisMfaFactorStore — what is Redis-specific", () => {
	it('declares kind "redis"', () => {
		expect(storeAt(freshPrefix()).kind).toBe("redis");
	});

	it("keeps one hash per subject, <prefix>{<subject>}, with a field per factor and no TTL", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await seed(store, RECORD({ id: "a" }));
		await seed(store, RECORD({ id: "b" }));
		await seed(store, RECORD({ id: "a", subject: "user-2" }));
		const key = `${prefix}{${keyPart("user-1")}}`;
		expect((await hashesAt(prefix)).sort()).toEqual(
			[key, `${prefix}{${keyPart("user-2")}}`].sort(),
		);
		expect(await first().type(key)).toBe("hash");
		expect((await first().hkeys(key)).sort()).toEqual([keyPart("a"), keyPart("b"), "~g"].sort());
		// No TTL: an enrolled factor does not expire, and a key with one would
		// be evictable under a volatile-* policy (ADR
		// 2026-09-25-multi-factor-authentication, D12).
		expect(await first().pttl(key)).toBe(-1);
		await store.update("user-1", "a", 1, { data: "v2.x", label: undefined, lastUsedAt: undefined });
		expect(await first().pttl(key)).toBe(-1);
	});

	it("puts a subject that carries a brace or a lone surrogate inside the tag, and apart from every other subject", async () => {
		// The subject is spelled as base64url of its JSON: no brace can move the
		// hash tag, and two subjects differing only in a lone surrogate — which
		// UTF-8 would turn into the same replacement character — never share a
		// hash.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const subjects = ["a}b", "{x}", "\uD800", "\uDBFF"];
		for (const subject of subjects) await seed(store, RECORD({ subject, data: subject }));
		for (const subject of subjects) {
			expect(await store.list(subject)).toStrictEqual([RECORD({ subject, data: subject })]);
		}
		expect(await hashesAt(prefix)).toHaveLength(subjects.length);
	});

	it("updates at a version without decoding the JSON: data, label and dates come back as written", async () => {
		// cjson re-encodes an empty array as an object, so a script that decoded
		// and re-encoded the record would turn "[]" into "{}" — and a label of
		// "[]" into an object. The compare-and-set never decodes it.
		const store = storeAt(freshPrefix());
		await seed(store, RECORD({ data: "{}", label: "[]" }));
		const next = { data: "[]", label: "{}", lastUsedAt: new Date("2026-09-03T00:00:00.123Z") };
		const updated = await store.update("user-1", "factor-1", 1, next);
		expect(updated).toStrictEqual({ ...RECORD({ data: "{}", label: "[]" }), ...next, version: 2 });
		expect(await store.list("user-1")).toStrictEqual([updated]);
	});

	it("answers null for a version that is not a whole number, and changes nothing", async () => {
		const store = storeAt(freshPrefix());
		await seed(store, RECORD());
		const next = { data: "v2.late", label: undefined, lastUsedAt: undefined };
		for (const version of [1.5, Number.NaN, -1, Number.POSITIVE_INFINITY]) {
			expect(await store.update("user-1", "factor-1", version, next), String(version)).toBeNull();
		}
		expect(await store.list("user-1")).toStrictEqual([RECORD()]);
	});

	it("refuses, with a RangeError and writing nothing, a record it could not read back", async () => {
		// Whatever a read would refuse — and a read refuses the subject's whole
		// list — is refused at the write instead: one bad record written would
		// make every factor of its subject unreadable. A date that is not one
		// reads back as no Date; a version that is not a whole number is one no
		// compare-and-set can match; a binding outside the four of ADR
		// 2026-09-25-multi-factor-authentication, D24, or a field that is not
		// the type the record declares, is not a record.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		for (const [name, overrides] of [
			["createdAt invalid", { createdAt: new Date(Number.NaN) }],
			["createdAt not a date", { createdAt: 1_700_000_000_000 }],
			["lastUsedAt invalid", { lastUsedAt: new Date(Number.NaN) }],
			["lastUsedAt not a date", { lastUsedAt: "2026-09-02" }],
			["version fractional", { version: 1.5 }],
			["version negative", { version: -1 }],
			["version NaN", { version: Number.NaN }],
			["binding outside the four", { binding: "admin" }],
			["binding null", { binding: null }],
			["kind not a string", { kind: 7 }],
			["data not a string", { data: 7 }],
			["data missing", { data: undefined }],
			["label not a string", { label: 7 }],
			["label null", { label: null }],
			["id not a string", { id: 7 }],
			["subject not a string", { subject: 7 }],
		] as const) {
			await expect(store.createIf(RECORD(overrides as never), null), name).rejects.toThrow(
				RangeError,
			);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
		await seed(store, RECORD());
		for (const [name, next] of [
			["lastUsedAt invalid", { data: "v2.x", label: undefined, lastUsedAt: new Date(Number.NaN) }],
			["lastUsedAt not a date", { data: "v2.x", label: undefined, lastUsedAt: 5 }],
			["data not a string", { data: 7, label: undefined, lastUsedAt: undefined }],
			["label not a string", { data: "v2.x", label: 7, lastUsedAt: undefined }],
			["label null", { data: "v2.x", label: null, lastUsedAt: undefined }],
		] as const) {
			await expect(store.update("user-1", "factor-1", 1, next as never), name).rejects.toThrow(
				RangeError,
			);
		}
		expect(await store.list("user-1")).toStrictEqual([RECORD()]);
	});

	it("refuses to list a subject whose hash holds a record it cannot read: never fewer factors than there are", async () => {
		// Only a subject with no record that may count opens a first binding
		// (ADR 2026-09-25-multi-factor-authentication, F3), so a record read as
		// absent would downgrade the account. The adapter throws — an outage,
		// 503 — and quotes nothing it read.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await seed(store, RECORD({ id: "good" }));
		const key = `${prefix}{${keyPart("user-1")}}`;
		for (const value of [
			"not a record",
			'1\n{"id":"bad"}\n{"data":"v2.x"}',
			`1\n${JSON.stringify({ id: "bad", subject: "user-2", kind: "totp", binding: null, createdAt: 1 })}\n${JSON.stringify({ data: "v2.x", label: null, lastUsedAt: null })}`,
			`one\n${JSON.stringify({ id: "bad", subject: "user-1", kind: "totp", binding: null, createdAt: 1 })}\n${JSON.stringify({ data: "v2.x", label: null, lastUsedAt: null })}`,
		]) {
			await first().hset(key, keyPart("bad"), value);
			const listed = store.list("user-1");
			await expect(listed).rejects.toThrow(/MfaFactorStore/);
			await expect(listed).rejects.not.toThrow(/user-2|v2\.x|not a record/);
		}
		// A record stored under another id's field is not that id's record either.
		const stray = `1\n${JSON.stringify({ id: "other", subject: "user-1", kind: "totp", binding: null, createdAt: 1 })}\n${JSON.stringify({ data: "v2.x", label: null, lastUsedAt: null })}`;
		await first().hset(key, keyPart("bad"), stray);
		await expect(store.list("user-1")).rejects.toThrow(/MfaFactorStore/);
	});

	it("refuses to list a record whose dates are no instant a Date holds as written — beyond ±8.64e15 ms, or a fraction of one — rather than answer an Invalid Date or another instant", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}{${keyPart("user-1")}}`;
		const field = keyPart("factor-1");
		const fixed = (createdAt: number): string =>
			JSON.stringify({ id: "factor-1", subject: "user-1", kind: "totp", binding: null, createdAt });
		const mutable = (lastUsedAt: number | null): string =>
			JSON.stringify({ data: "v2.x", label: null, lastUsedAt });
		for (const [name, value] of [
			["createdAt past the Date range", `1\n${fixed(8_640_000_000_000_001)}\n${mutable(null)}`],
			["createdAt before it", `1\n${fixed(-8_640_000_000_000_001)}\n${mutable(null)}`],
			["createdAt a fraction", `1\n${fixed(1.5)}\n${mutable(null)}`],
			["lastUsedAt past the Date range", `1\n${fixed(1)}\n${mutable(1e300)}`],
			["lastUsedAt a fraction", `1\n${fixed(1)}\n${mutable(0.25)}`],
		] as const) {
			await first().hset(key, field, value);
			await expect(store.list("user-1"), name).rejects.toThrow(/MfaFactorStore/);
		}
		// Whole instants at the edges of the range read.
		await first().hset(
			key,
			field,
			`1\n${fixed(-8_640_000_000_000_000)}\n${mutable(8_640_000_000_000_000)}`,
		);
		const [read] = await store.list("user-1");
		expect(read?.createdAt.getTime()).toBe(-8_640_000_000_000_000);
		expect(read?.lastUsedAt?.getTime()).toBe(8_640_000_000_000_000);
	});

	it("refuses, with a RangeError and writing nothing, a date whose time value is no instant a read would take back", async () => {
		// A Date's own time value is always one; what the adapter reads is
		// `getTime()`, which an object passed off as a Date can answer as it likes.
		const lying = (ms: number): Date => {
			const date = new Date(0);
			Object.defineProperty(date, "getTime", { value: () => ms });
			return date;
		};
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		for (const ms of [8_640_000_000_000_001, -8_640_000_000_000_001, 1.5]) {
			await expect(
				store.createIf(RECORD({ createdAt: lying(ms) }), null),
				String(ms),
			).rejects.toThrow(RangeError);
			await expect(
				store.createIf(RECORD({ lastUsedAt: lying(ms) }), null),
				String(ms),
			).rejects.toThrow(RangeError);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
		await seed(store, RECORD());
		for (const ms of [8_640_000_000_000_001, 1.5]) {
			await expect(
				store.update("user-1", "factor-1", 1, {
					data: "v2.x",
					label: undefined,
					lastUsedAt: lying(ms),
				}),
				String(ms),
			).rejects.toThrow(RangeError);
		}
		expect(await store.list("user-1")).toStrictEqual([RECORD()]);
	});

	it("answers null to an update of a value that is not exactly three lines, and leaves it as it was: the compare-and-set never rewrites a record it would have to cut", async () => {
		// MfaFactorStoreClient.update's contract. A fourth line — even an empty
		// one — is a record this adapter did not write; carrying over the first
		// two lines and dropping the rest would pass it off as one it did.
		const prefix = freshPrefix();
		const client = makeIoredisMfaFactorStoreClient(first());
		const key = `${prefix}{${keyPart("user-1")}}`;
		const field = keyPart("factor-1");
		const fixed = JSON.stringify({
			id: "factor-1",
			subject: "user-1",
			kind: "totp",
			binding: null,
			createdAt: 1,
		});
		const mutable = JSON.stringify({ data: "v2.x", label: null, lastUsedAt: null });
		for (const value of [
			`1\n${fixed}\n${mutable}\nextra`,
			`1\n${fixed}\n${mutable}\n`,
			`1\n${fixed}\n${mutable}\n\n`,
			`1\n${fixed}`,
		]) {
			await first().hset(key, field, value);
			expect(
				await client.update(key, field, { expectedVersion: "1", nextVersion: "2", mutable }),
				JSON.stringify(value),
			).toBeNull();
			expect(await first().hget(key, field), JSON.stringify(value)).toBe(value);
		}
	});

	it("refuses a keyPrefix that carries a brace, which would take the subject's hash tag over", () => {
		for (const keyPrefix of ["mfaf:{x}:", "mfaf}:", "{mfaf:"]) {
			expect(() => storeAt(keyPrefix), keyPrefix).toThrow(RangeError);
		}
	});
});

/** The clock skew the adapter declares between the app's and Redis's clocks. */
const SKEW_MS = 1_000;

/** A generation as a store answers one, for a probe that hands one in. */
const generation = (value: string): StoreGeneration => value as StoreGeneration;

/** The factor's id as the provider makes one: `name` padded to 22 base64url characters. */
const factorId = (name: string): string => name.padEnd(22, "A");
const FACTOR_A = factorId("a");
const FACTOR_B = factorId("b");

/** The generation a write that had to land answered. */
const landed = (answer: {
	readonly outcome: string;
	readonly generation?: StoreGeneration;
}): StoreGeneration => {
	expect(answer.outcome).toMatch(/^(created|removed)$/);
	return answer.generation as StoreGeneration;
};

/** Whether `pttl` is a tombstone's retention, started within the last minute. */
const freshTombstone = (pttl: number): boolean =>
	pttl > BUNDLED_STORE_WRITE_LIFETIME_MS - 60_000 && pttl <= BUNDLED_STORE_WRITE_LIFETIME_MS;

describe("createRedisMfaFactorStore — the set's generation and its tombstone", () => {
	it("keeps the set's generation under ~g, answers it from listVersioned, never as a record, and sets no TTL while the set holds a factor", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		const created = landed(await store.createIf(RECORD({ id: FACTOR_A }), null));
		expect(await first().hget(key, "~g")).toBe(created);
		expect(await first().pttl(key)).toBe(-1);
		expect(await store.listVersioned("user-1")).toStrictEqual({
			generation: created,
			items: [RECORD({ id: FACTOR_A })],
		});
		expect(await store.list("user-1")).toStrictEqual([RECORD({ id: FACTOR_A })]);
	});

	it("keeps a set its last removal empties as a tombstone for the bundled write lifetime, and takes the expiry off when a factor is added again", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		const created = landed(await store.createIf(RECORD({ id: FACTOR_A }), null));
		const emptied = landed(await store.removeIf("user-1", FACTOR_A, created));
		expect(await first().hgetall(key)).toStrictEqual({ "~g": emptied });
		expect(freshTombstone(await first().pttl(key))).toBe(true);
		expect(await store.list("user-1")).toStrictEqual([]);

		landed(await store.createIf(RECORD({ id: FACTOR_B }), emptied));
		expect(await first().pttl(key)).toBe(-1);
	});

	it("starts the tombstone's retention again at every reset: of a set holding factors, of an emptied one, and of one never written", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		await store.removeAllForSubject("user-1");
		expect(freshTombstone(await first().pttl(key))).toBe(true);
		const tombstone = await first().hget(key, "~g");

		await first().pexpire(key, 60_000);
		await store.removeAllForSubject("user-1");
		expect(freshTombstone(await first().pttl(key))).toBe(true);
		expect(await first().hget(key, "~g")).not.toBe(tombstone);

		await seed(store, RECORD({ id: FACTOR_A }));
		await store.removeAllForSubject("user-1");
		expect(await first().hkeys(key)).toStrictEqual(["~g"]);
		expect(freshTombstone(await first().pttl(key))).toBe(true);
	});

	it("refuses to read a set whose generation is not one a store answers, quoting nothing it read", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		await seed(store, RECORD({ id: FACTOR_A }));
		for (const value of ['bad"generation', "", "x".repeat(129)]) {
			await first().hset(key, "~g", value);
			const read = store.listVersioned("user-1");
			await expect(read, JSON.stringify(value)).rejects.toThrow(/MfaFactorStore/);
			await expect(read).rejects.not.toThrow(/bad/);
		}
	});

	it("refuses a versioned read of a hash holding a field named __proto__, as the plain read does: never fewer factors than there are", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await seed(store, RECORD({ id: FACTOR_A }));
		await first().hset(keyAt(prefix, "user-1"), "__proto__", "not a record");
		await expect(store.list("user-1")).rejects.toThrow(/MfaFactorStore/);
		await expect(store.listVersioned("user-1")).rejects.toThrow(/MfaFactorStore/);
	});

	it("refuses, with a RangeError and writing nothing, an expected generation no store answers", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		for (const expected of ["", 'a"b', "x".repeat(129), 7]) {
			await expect(
				store.createIf(RECORD({ id: FACTOR_A }), expected as never),
				String(expected),
			).rejects.toThrow(RangeError);
			await expect(store.removeIf("user-1", FACTOR_A, expected as never)).rejects.toThrow(
				RangeError,
			);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
	});
});

describe("createRedisMfaFactorStore — a hash written before the set had a generation", () => {
	/** A subject's hash holding factor A and no `~g`, as a build from before the set members leaves one. */
	const legacy = async (prefix: string): Promise<{ store: MfaFactorStore; key: string }> => {
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		await seed(store, RECORD({ id: FACTOR_A }));
		await first().hdel(key, "~g");
		return { store, key };
	};

	it("answers conflict to every conditional write against it, and gives it no generation", async () => {
		const prefix = freshPrefix();
		const { store, key } = await legacy(prefix);
		const before = await first().hgetall(key);
		expect(await store.createIf(RECORD({ id: FACTOR_B }), generation("any-g"))).toStrictEqual({
			outcome: "conflict",
		});
		expect(await store.createIf(RECORD({ id: FACTOR_B }), null)).toStrictEqual({
			outcome: "conflict",
		});
		expect(await store.removeIf("user-1", FACTOR_A, generation("any-g"))).toStrictEqual({
			outcome: "conflict",
		});
		expect(await first().hgetall(key)).toStrictEqual(before);
	});

	it("is given a fresh generation by its first versioned read, which keeps its expiry; later reads answer the same one, and a write at it lands", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = keyAt(prefix, "user-1");
		await seed(store, RECORD({ id: FACTOR_A }));
		const earlier = await first().hget(key, "~g");
		await first().hdel(key, "~g");
		await first().pexpire(key, 600_000);

		const read = await store.listVersioned("user-1");
		const minted = read.generation as StoreGeneration;
		expect(read.items).toStrictEqual([RECORD({ id: FACTOR_A })]);
		expect(minted).not.toBe(earlier);
		expect(await first().hget(key, "~g")).toBe(minted);
		const pttl = await first().pttl(key);
		expect(pttl > 0 && pttl <= 600_000).toBe(true);
		expect((await storeAt(prefix, second()).listVersioned("user-1")).generation).toBe(minted);
		landed(await store.removeIf("user-1", FACTOR_A, minted));
	});
});

/** A membership script's top-level statements: what runs, in order, once its functions are defined. */
const topLevel = (source: string): string[] =>
	source
		.split("\n")
		.filter(
			(line) =>
				line !== "" &&
				!line.startsWith("#!lua") &&
				line !== "end" &&
				!line.startsWith("local function ") &&
				!/^\s/.test(line),
		);

describe("createRedisMfaFactorStore — a membership write past its deadline", () => {
	const SCRIPTS = {
		createIf: MFA_FACTOR_CREATE_IF,
		removeIf: MFA_FACTOR_REMOVE_IF,
		removeAll: MFA_FACTOR_REMOVE_ALL,
	};

	it.each(Object.entries(SCRIPTS))(
		"%s's script answers a copy with the first answer, then refuses a write past its deadline, before it reads or writes the set",
		(_, script) => {
			expect(topLevel(script.source)).toStrictEqual([
				"local applied = redis.call('GET', KEYS[2])",
				"if applied then return applied end",
				"if mfa_factor_late() then return 'late' end",
				"local outcome = apply()",
				"redis.call('SET', KEYS[2], outcome, 'PXAT', tonumber(ARGV[2]) + tonumber(ARGV[3]) + 1)",
				"return outcome",
			]);
		},
	);

	it.each(Object.entries(SCRIPTS))(
		"%s's script refuses a write the server takes at its deadline, to the millisecond, and lets through one taken a millisecond before it",
		async (_, script) => {
			// The server's clock is pinned: a local `redis` ahead of the script's
			// own text answers `TIME` with a fixed instant and `GET` (the replay key)
			// with nothing, and fails any other call, which only a write let past
			// the deadline check makes. The `#!lua` line, which must be the first,
			// is left off; nothing here reaches the server's keys.
			const instantMs = 1_700_000_000_123;
			const pinned = `local redis = { call = function(command)
  if command == 'TIME' then return { '1700000000', '123456' } end
  if command == 'GET' then return false end
  error('let through: ' .. command)
end }
${script.source.slice(script.source.indexOf("\n") + 1)}`;
			const key = keyAt(freshPrefix(), "user-1");
			const run = (deadlineMs: number): Promise<unknown> =>
				first().eval(
					pinned,
					2,
					key,
					`${key}:w:pinned`,
					"pinned",
					String(deadlineMs),
					String(SKEW_MS),
					"",
					"field",
					"value",
				);
			expect(await run(instantMs)).toBe("late");
			expect(await run(instantMs - 1)).toBe("late");
			await expect(run(instantMs + 1)).rejects.toThrow(/let through/);
		},
	);

	it("lets the removal, the reset and the versioned read run on a full server, and keeps the create refused there", () => {
		// Under `noeviction` a full Redis refuses a `#!lua` script without
		// `allow-oom`. A removal, the reset and the read a removal starts from
		// write only `~g`, the replay key and an expiry; an attacker's factor
		// must still be removable, and the reset must still run.
		for (const script of [MFA_FACTOR_REMOVE_IF, MFA_FACTOR_REMOVE_ALL, MFA_FACTOR_LIST_VERSIONED]) {
			expect(script.source.split("\n")[0]).toBe("#!lua flags=allow-oom");
		}
		expect(MFA_FACTOR_CREATE_IF.source.split("\n")[0]).toBe("#!lua");
	});

	it("declares its write lifetime as the write timeout plus the clock skew, well under the bound", () => {
		expect(REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS).toBe(2_000);
		expect(REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS * 1_000).toBeLessThan(
			BUNDLED_STORE_WRITE_LIFETIME_MS,
		);
	});

	it("answers late, and writes nothing, for every membership write the server takes past its deadline; within it, each commits", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const client = makeIoredisMfaFactorStoreClient(first());
		const key = keyAt(prefix, "user-1");
		const at = landed(await store.createIf(RECORD({ id: FACTOR_A }), null));
		const fieldA = keyPart(FACTOR_A);
		const fieldB = keyPart(FACTOR_B);
		const value = (await first().hget(key, fieldA)) as string;
		const now = await serverClock(first)();
		const past = now - 1;
		const tombstoneMs = BUNDLED_STORE_WRITE_LIFETIME_MS;
		const before = { fields: await first().hgetall(key), pttl: await first().pttl(key) };

		expect(
			await client.createIf(key, fieldB, value, {
				next: "n1",
				replayKey: `${key}:w:n1`,
				clockSkewMs: SKEW_MS,
				deadlineMs: past,
				expected: at,
			}),
		).toBe("late");
		expect(
			await client.removeIf(key, fieldA, {
				next: "n2",
				replayKey: `${key}:w:n2`,
				clockSkewMs: SKEW_MS,
				deadlineMs: past,
				tombstoneMs,
				expected: at,
			}),
		).toBe("late");
		expect(
			await client.removeAll(key, {
				next: "n3",
				replayKey: `${key}:w:n3`,
				clockSkewMs: SKEW_MS,
				deadlineMs: past,
				tombstoneMs,
			}),
		).toBe("late");
		const absent = keyAt(prefix, "nobody");
		expect(
			await client.removeAll(absent, {
				next: "n4",
				replayKey: `${absent}:w:n4`,
				clockSkewMs: SKEW_MS,
				deadlineMs: past,
				tombstoneMs,
			}),
		).toBe("late");
		expect({ fields: await first().hgetall(key), pttl: await first().pttl(key) }).toStrictEqual(
			before,
		);
		expect(await first().exists(absent)).toBe(0);

		const future = now + 60_000;
		expect(
			await client.createIf(key, fieldB, value, {
				next: "n5",
				replayKey: `${key}:w:n5`,
				clockSkewMs: SKEW_MS,
				deadlineMs: future,
				expected: at,
			}),
		).toBe("created");
		expect(
			await client.removeIf(key, fieldB, {
				next: "n6",
				replayKey: `${key}:w:n6`,
				clockSkewMs: SKEW_MS,
				deadlineMs: future,
				tombstoneMs,
				expected: generation("n5"),
			}),
		).toBe("removed");
		expect(
			await client.removeAll(key, {
				next: "n7",
				replayKey: `${key}:w:n7`,
				clockSkewMs: SKEW_MS,
				deadlineMs: future,
				tombstoneMs,
			}),
		).toBe("removed");
		expect(await first().hgetall(key)).toStrictEqual({ "~g": "n7" });
	});

	it("answers a copy of a membership write sent again within its deadline with the first one's outcome, and writes nothing again", async () => {
		// ioredis sends again a command whose reply a dropped connection lost;
		// the first copy may have run. A copy must neither write a generation
		// already issued back over a later one, nor answer conflict for a write
		// that landed.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const client = makeIoredisMfaFactorStoreClient(first());
		const key = keyAt(prefix, "user-1");
		const fieldA = keyPart(FACTOR_A);
		const fieldB = keyPart(FACTOR_B);
		await seed(store, RECORD({ id: FACTOR_A }));
		const value = (await first().hget(key, fieldA)) as string;
		const deadlineMs = (await serverClock(first)()) + 60_000;
		const tombstoneMs = BUNDLED_STORE_WRITE_LIFETIME_MS;
		const replayKey = (next: string): string => `${key}:w:${next}`;
		const clockSkewMs = SKEW_MS;

		const reset = {
			next: "reset-g",
			deadlineMs,
			tombstoneMs,
			replayKey: replayKey("reset-g"),
			clockSkewMs,
		};
		expect(await client.removeAll(key, reset)).toBe("removed");
		const later = landed(await store.createIf(RECORD({ id: FACTOR_A }), generation("reset-g")));
		expect(await client.removeAll(key, reset)).toBe("removed");
		expect(await first().hget(key, "~g")).toBe(later);
		expect(await first().hexists(key, fieldA)).toBe(1);

		const create = {
			next: "create-g",
			deadlineMs,
			expected: later,
			replayKey: replayKey("create-g"),
			clockSkewMs,
		};
		expect(await client.createIf(key, fieldB, value, create)).toBe("created");
		expect(await client.createIf(key, fieldB, value, create)).toBe("created");
		const removal = {
			next: "remove-g",
			deadlineMs,
			tombstoneMs,
			expected: generation("create-g"),
			replayKey: replayKey("remove-g"),
			clockSkewMs,
		};
		expect(await client.removeIf(key, fieldB, removal)).toBe("removed");
		expect(await client.removeIf(key, fieldB, removal)).toBe("removed");
		expect(await first().hget(key, "~g")).toBe("remove-g");
		expect(await first().hexists(key, fieldB)).toBe(0);

		// A copy's answer is kept until the declared clock skew past its
		// deadline, so a copy that a server whose clock lags the one that
		// judged the deadline (after a failover or a slot migration) still finds
		// it; past that, the copy is late.
		const pttl = await first().pttl(replayKey("reset-g"));
		const now = await serverClock(first)();
		expect(pttl).toBeGreaterThan(deadlineMs + SKEW_MS - now - 5_000);
		expect(pttl).toBeLessThanOrEqual(deadlineMs + SKEW_MS + 1 - now + 5_000);
		expect(await first().pexpiretime(replayKey("reset-g"))).toBe(deadlineMs + SKEW_MS + 1);
	});

	it("rejects, as an outage whose outcome is unknown, a membership write its client answers late", async () => {
		// `late` says only that the copy the server judged wrote nothing: a copy
		// resent after an earlier one committed, once its replay key had gone,
		// answers `late` too. So the rejection never says nothing was written.
		const prefix = freshPrefix();
		const real = makeIoredisMfaFactorStoreClient(first());
		const store = createRedisMfaFactorStore({
			keyPrefix: prefix,
			client: {
				...real,
				createIf: async () => "late",
				removeIf: async () => "late",
				removeAll: async () => "late",
			},
		});
		const writes: (() => Promise<unknown>)[] = [
			() => store.createIf(RECORD({ id: FACTOR_A }), null),
			() => store.removeIf("user-1", FACTOR_A, generation("g")),
			() => store.removeAllForSubject("user-1"),
		];
		for (const write of writes) {
			const error = await write().then(
				() => undefined,
				(rejected: unknown) => rejected,
			);
			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toMatch(/past its deadline; the outcome is unknown/);
			expect((error as Error).message).toMatch(
				/another copy may have committed, or may still commit within W/,
			);
			expect((error as Error).message).not.toMatch(/wrote nothing/);
		}
	});
});

/**
 * Cases that pause a whole server, or need one that is a replica: each on a
 * container of its own, so no other file's server stalls or changes role.
 */
describe("createRedisMfaFactorStore — on a server of its own", () => {
	let paused: StartedTestContainer | undefined;
	let replica: StartedTestContainer | undefined;
	const opened: Redis[] = [];

	const open = (container: StartedTestContainer | undefined): Redis => {
		if (container === undefined) throw new Error("the container did not start");
		const io = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
		io.on("error", () => {});
		opened.push(io);
		return io;
	};

	beforeAll(async () => {
		[paused, replica] = await Promise.all([
			new GenericContainer("redis:7.2-alpine")
				.withExposedPorts(6379)
				.withStartupTimeout(60_000)
				.start(),
			// A replica of a primary that is not there: read-only, and serving
			// what it holds (`replica-serve-stale-data yes`, the default).
			new GenericContainer("redis:7.2-alpine")
				.withCommand(["redis-server", "--replicaof", "127.0.0.1", "1"])
				.withExposedPorts(6379)
				.withStartupTimeout(60_000)
				.start(),
		]);
	}, 120_000);

	afterAll(async () => {
		for (const io of opened) io.disconnect();
		await Promise.all([paused?.stop(), replica?.stop()]);
	});

	it("is refused by a read-only replica for the versioned read and every membership write, where a plain read is served", async () => {
		const io = open(replica);
		const store = storeAt("mfaf:", io);
		expect(await io.hgetall(keyAt("mfaf:", "user-1"))).toStrictEqual({});
		await expect(store.listVersioned("user-1")).rejects.toThrow(/READONLY/);
		await expect(store.createIf(RECORD({ id: FACTOR_A }), null)).rejects.toThrow(/READONLY/);
		await expect(store.removeIf("user-1", FACTOR_A, generation("g"))).rejects.toThrow(/READONLY/);
		await expect(store.removeAllForSubject("user-1")).rejects.toThrow(/READONLY/);
	});

	it("removes a factor, resets the set and reads it on a full noeviction server, where a create is refused", async () => {
		const admin = open(paused);
		const prefix = freshPrefix();
		const store = storeAt(prefix, admin);
		await seed(store, RECORD({ id: FACTOR_A }));
		await seed(store, RECORD({ id: FACTOR_B }));
		const at = (await store.listVersioned("user-1")).generation as StoreGeneration;
		await admin.config("SET", "maxmemory-policy", "noeviction");
		await admin.config("SET", "maxmemory", "1");
		try {
			await expect(store.createIf(RECORD({ id: factorId("c") }), at)).rejects.toThrow(/OOM/);
			const read = await store.listVersioned("user-1");
			expect(read.generation).toBe(at);
			const removed = landed(await store.removeIf("user-1", FACTOR_A, at));
			await store.removeAllForSubject("user-1");
			const reset = await store.listVersioned("user-1");
			expect(reset.items).toStrictEqual([]);
			expect(reset.generation).not.toBe(removed);
		} finally {
			await admin.config("SET", "maxmemory", "0");
		}
	});

	it("ends the wait at the write timeout for a write a stalled server holds, and the write, taken past its deadline, writes nothing", async () => {
		const admin = open(paused);
		const io = open(paused);
		const prefix = freshPrefix();
		const store = storeAt(prefix, io);
		const at = landed(await store.createIf(RECORD({ id: FACTOR_A }), null));

		await admin.call("CLIENT", "PAUSE", "2500", "WRITE");
		const started = Date.now();
		await expect(store.createIf(RECORD({ id: FACTOR_B }), at)).rejects.toThrow(
			/no answer within 1000 ms; it may have committed, or may still commit within W/,
		);
		const waited = Date.now() - started;
		expect(waited).toBeGreaterThanOrEqual(900);
		expect(waited).toBeLessThan(2_000);
		// Queued behind the held write on the same socket: answered once it ran.
		await io.ping();
		expect(Date.now() - started).toBeGreaterThanOrEqual(2_000);
		expect(await store.listVersioned("user-1")).toStrictEqual({
			generation: at,
			items: [RECORD({ id: FACTOR_A })],
		});
	});

	it("writes nothing for a write the driver sends again after a reconnect past its deadline, where within it the same resend commits", async () => {
		const admin = open(paused);
		const prefix = freshPrefix();
		const key = keyAt(prefix, "user-1");
		const at = landed(await storeAt(prefix, admin).createIf(RECORD({ id: FACTOR_A }), null));
		const value = (await admin.hget(key, keyPart(FACTOR_A))) as string;

		/**
		 * A conditional create sent on a connection the server then drops while
		 * a pause holds the command: ioredis sends it again once it reconnects,
		 * after the pause. Resolves what the resent command answered.
		 */
		const resent = async (field: string, next: string, deadlineAfterMs: number) => {
			const io = open(paused);
			const client = makeIoredisMfaFactorStoreClient(io);
			let reconnected = false;
			io.on("reconnecting", () => {
				reconnected = true;
			});
			const id = String(await io.client("ID"));
			const now = await serverClock(() => admin)();
			await admin.call("CLIENT", "PAUSE", "2000", "WRITE");
			const reply = client.createIf(key, field, value, {
				next,
				replayKey: `${key}:w:${next}`,
				clockSkewMs: SKEW_MS,
				deadlineMs: now + deadlineAfterMs,
				expected: at,
			});
			await new Promise((resolve) => setTimeout(resolve, 200));
			await admin.call("CLIENT", "KILL", "ID", id);
			const answer = await reply;
			expect(reconnected).toBe(true);
			return answer;
		};

		expect(await resent(keyPart(FACTOR_B), "resent-late", 300)).toBe("late");
		expect(await admin.hgetall(key)).toStrictEqual({ [keyPart(FACTOR_A)]: value, "~g": at });

		expect(await resent(keyPart(FACTOR_B), "resent-in-time", 60_000)).toBe("created");
		expect(await admin.hget(key, "~g")).toBe("resent-in-time");
	});
});
