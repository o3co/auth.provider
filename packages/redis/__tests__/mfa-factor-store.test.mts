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
 * against the test kit's contract suite, on a real Redis, and what is Redis-specific below
 * it: one hash per subject with a field per factor, no TTL, a compare-and-set
 * that never decodes the JSON, and a stored record this adapter cannot read
 * refused rather than read as no factor (same ADR, D12 and D28).
 *
 * The contract's store alternates between two connections, so the races the
 * suite sets up are races across sockets, as in a deployment.
 */

import type { MfaFactorRecord, MfaFactorStore } from "@o3co/auth-provider-core";
import { mfaFactorStoreContract } from "@o3co/auth-provider-test-kit";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisMfaFactorStoreClient } from "#/ioredis.mjs";
import { createRedisMfaFactorStore } from "#/mfa-factor-store.mjs";
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

const first = (): Redis => connections[0] as Redis;

/** How the adapter spells a value inside a key or a field — looked at from outside, as the probes must. */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/** A keyspace of its own for each case. */
const freshPrefix = (): string => {
	run += 1;
	return `mfaf:test-${run}:`;
};

/** One store per connection over one keyspace, every call taken in turn. */
const alternating = (keyPrefix: string): MfaFactorStore => {
	const stores = connections.map((connection) =>
		createRedisMfaFactorStore({ client: makeIoredisMfaFactorStoreClient(connection), keyPrefix }),
	);
	let next = 0;
	const pick = (): MfaFactorStore => {
		const store = stores[next % stores.length] as MfaFactorStore;
		next += 1;
		return store;
	};
	return {
		kind: "redis",
		list: (subject) => pick().list(subject),
		create: (record) => pick().create(record),
		update: (subject, id, expectedVersion, next) =>
			pick().update(subject, id, expectedVersion, next),
		remove: (subject, id) => pick().remove(subject, id),
		removeAllForSubject: (subject) => pick().removeAllForSubject(subject),
	};
};

describe("MfaFactorStore contract", () => {
	for (const contractCase of mfaFactorStoreContract({
		build: async () => ({ store: alternating(freshPrefix()) }),
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

const storeAt = (keyPrefix: string, connection: Redis = first()): MfaFactorStore =>
	createRedisMfaFactorStore({ client: makeIoredisMfaFactorStoreClient(connection), keyPrefix });

describe("createRedisMfaFactorStore — what is Redis-specific", () => {
	it('declares kind "redis"', () => {
		expect(storeAt(freshPrefix()).kind).toBe("redis");
	});

	it("keeps one hash per subject, <prefix>{<subject>}, with a field per factor and no TTL", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(RECORD({ id: "a" }));
		await store.create(RECORD({ id: "b" }));
		await store.create(RECORD({ id: "a", subject: "user-2" }));
		const key = `${prefix}{${keyPart("user-1")}}`;
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[key, `${prefix}{${keyPart("user-2")}}`].sort(),
		);
		expect(await first().type(key)).toBe("hash");
		expect((await first().hkeys(key)).sort()).toEqual([keyPart("a"), keyPart("b")].sort());
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
		for (const subject of subjects) await store.create(RECORD({ subject, data: subject }));
		for (const subject of subjects) {
			expect(await store.list(subject)).toStrictEqual([RECORD({ subject, data: subject })]);
		}
		expect(await first().keys(`${prefix}*`)).toHaveLength(subjects.length);
	});

	it("updates at a version without decoding the JSON: data, label and dates come back as written", async () => {
		// cjson re-encodes an empty array as an object, so a script that decoded
		// and re-encoded the record would turn "[]" into "{}" — and a label of
		// "[]" into an object. The compare-and-set never decodes it.
		const store = storeAt(freshPrefix());
		await store.create(RECORD({ data: "{}", label: "[]" }));
		const next = { data: "[]", label: "{}", lastUsedAt: new Date("2026-09-03T00:00:00.123Z") };
		const updated = await store.update("user-1", "factor-1", 1, next);
		expect(updated).toStrictEqual({ ...RECORD({ data: "{}", label: "[]" }), ...next, version: 2 });
		expect(await store.list("user-1")).toStrictEqual([updated]);
	});

	it("answers null for a version that is not a whole number, and changes nothing", async () => {
		const store = storeAt(freshPrefix());
		await store.create(RECORD());
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
		// compare-and-set can match; a binding outside the three of ADR
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
			["binding outside the three", { binding: "admin" }],
			["binding null", { binding: null }],
			["kind not a string", { kind: 7 }],
			["data not a string", { data: 7 }],
			["data missing", { data: undefined }],
			["label not a string", { label: 7 }],
			["label null", { label: null }],
			["id not a string", { id: 7 }],
			["subject not a string", { subject: 7 }],
		] as const) {
			await expect(store.create(RECORD(overrides as never)), name).rejects.toThrow(RangeError);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
		await store.create(RECORD());
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
		// Only zero records open a first binding (ADR
		// 2026-09-25-multi-factor-authentication, F3), so a record read as
		// absent would downgrade the account. The adapter throws — an outage,
		// 503 — and quotes nothing it read.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(RECORD({ id: "good" }));
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
			await expect(store.create(RECORD({ createdAt: lying(ms) })), String(ms)).rejects.toThrow(
				RangeError,
			);
			await expect(store.create(RECORD({ lastUsedAt: lying(ms) })), String(ms)).rejects.toThrow(
				RangeError,
			);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
		await store.create(RECORD());
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
