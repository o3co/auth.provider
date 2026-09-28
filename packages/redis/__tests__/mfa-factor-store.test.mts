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
 * The Redis `MfaFactorStore` (the MFA ADR's D7) against core's contract, on a
 * real Redis, and what is Redis-specific below it: one hash per subject with a
 * field per factor, no TTL, a compare-and-set that never decodes the JSON, and
 * a stored record this adapter cannot read refused rather than read as no
 * factor (D12, D28).
 *
 * Two connections, and the contract's store alternates between them, so the
 * races the suite sets up are races across sockets — what a deployment has —
 * rather than calls queued on one client.
 */

import type { MfaFactorRecord, MfaFactorStore } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisMfaFactorStoreClient } from "#/ioredis.mjs";
import { createRedisMfaFactorStore } from "#/mfa-factor-store.mjs";
import { runMfaFactorStoreContract } from "./adapters.mfa-factor-store.contract.mjs";
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

runMfaFactorStoreContract(async () => alternating(freshPrefix()));

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

describe("createRedisMfaFactorStore — what is Redis-specific (the MFA ADR's D7)", () => {
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
		// be evictable under a volatile-* policy (D12).
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
		// A date that is not one is stored as nothing a reader can turn back
		// into a Date, and a version that is not a whole number is one no
		// compare-and-set can ever match.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		for (const [name, overrides] of [
			["createdAt invalid", { createdAt: new Date(Number.NaN) }],
			["lastUsedAt invalid", { lastUsedAt: new Date(Number.NaN) }],
			["version fractional", { version: 1.5 }],
			["version negative", { version: -1 }],
			["version NaN", { version: Number.NaN }],
		] as const) {
			await expect(store.create(RECORD(overrides)), name).rejects.toThrow(RangeError);
		}
		expect(await first().keys(`${prefix}*`)).toEqual([]);
		await store.create(RECORD());
		await expect(
			store.update("user-1", "factor-1", 1, {
				data: "v2.x",
				label: undefined,
				lastUsedAt: new Date(Number.NaN),
			}),
		).rejects.toThrow(RangeError);
		expect(await store.list("user-1")).toStrictEqual([RECORD()]);
	});

	it("refuses to list a subject whose hash holds a record it cannot read: never fewer factors than there are", async () => {
		// Only zero records open a first binding (F3), so a record read as
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

	it("refuses a keyPrefix that carries a brace, which would take the subject's hash tag over", () => {
		for (const keyPrefix of ["mfaf:{x}:", "mfaf}:", "{mfaf:"]) {
			expect(() => storeAt(keyPrefix), keyPrefix).toThrow(RangeError);
		}
	});
});
