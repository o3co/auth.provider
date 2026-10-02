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
 * The wire format of the Store's MFA endpoints: a factor record and an
 * update's changes as JSON carries them. Times are epoch milliseconds named
 * `…Ms`; an optional field with no value is left out, and `null` is never
 * read as "unset". The fields a page shows are held to the record's shape: an
 * id of 22 base64url characters, a kind of the hint grammar, a label of 1 to
 * 64 printable characters; a record breaking one is unreadable. A list is
 * read whole: one unreadable record, one naming another subject, or two
 * with one id refuse it. What a writer makes, the reader reads back whole;
 * what the reader would refuse, the writer refuses with a `RangeError`. An
 * update names the record by `subject` and `id` and carries the expected
 * version and, as its changes, only `data`, `label` and `lastUsedAtMs`.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { StoreGeneration } from "#/adapters/conditionalWrite.mjs";
import { MAX_STORABLE_EXPIRY_MS } from "#/adapters/expiry.mjs";
import type { MfaFactorRecord, MfaFactorRecordUpdate } from "#/mfa/factorStore.mjs";
import {
	fromMfaStoreFactor,
	type MfaStoreCreateIfRequest,
	type MfaStoreDeleteRequest,
	type MfaStoreFactor,
	type MfaStoreFactorBinding,
	type MfaStoreFactorChanges,
	type MfaStoreRemoveIfRequest,
	type MfaStoreUpdateRequest,
	readMfaStoreCreateIfAnswer,
	readMfaStoreFactor,
	readMfaStoreFactorChanges,
	readMfaStoreListAnswer,
	readMfaStoreRemoveIfAnswer,
	readMfaStoreVersionedListAnswer,
	toMfaStoreCreateIfRequest,
	toMfaStoreFactor,
	toMfaStoreFactorChanges,
	toMfaStoreRemoveIfRequest,
	toMfaStoreUpdateRequest,
} from "#/mfa/storeWire.mjs";

/** Factor ids as the provider makes them: 16 random bytes, base64url. */
const ID_1 = "u1PIlRkb_cy7UmjYUKaL_A";
const ID_2 = "TO-Ylhtepgp2qoDTXRcOnQ";

const FULL: MfaFactorRecord = {
	id: ID_1,
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 3,
	data: "v2.opaque-sealed-data",
};

const BARE: MfaFactorRecord = {
	...FULL,
	id: ID_2,
	label: undefined,
	binding: undefined,
	lastUsedAt: undefined,
};

const FULL_WIRE: MfaStoreFactor = {
	id: ID_1,
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAtMs: Date.parse("2026-09-01T00:00:00.000Z"),
	lastUsedAtMs: Date.parse("2026-09-02T00:00:00.000Z"),
	version: 3,
	data: "v2.opaque-sealed-data",
};

/** A conditional write's deadline: the send time plus the adapter's request timeout, on the provider's clock. */
const DEADLINE_MS = Date.parse("2026-09-03T00:00:05.000Z");

/** Deadlines no conditional write may carry: each is not a whole instant above 0 within the Date range. */
const NOT_DEADLINES: readonly unknown[] = [
	0,
	-1,
	1.5,
	Number.NaN,
	Number.POSITIVE_INFINITY,
	Number.NEGATIVE_INFINITY,
	MAX_STORABLE_EXPIRY_MS + 1,
	Number.MAX_SAFE_INTEGER,
	Number.MAX_SAFE_INTEGER + 1,
	String(DEADLINE_MS),
	BigInt(DEADLINE_MS),
	new Date(DEADLINE_MS),
	null,
	undefined,
];

/** `value` as it arrives after a trip through JSON. */
const overJson = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

describe("a factor record on the wire", () => {
	it("names four bindings: password, email_proof, federated and mfa", () => {
		expectTypeOf<MfaStoreFactorBinding>().toEqualTypeOf<
			"password" | "email_proof" | "federated" | "mfa"
		>();
		expectTypeOf<MfaFactorRecord["binding"]>().toEqualTypeOf<MfaStoreFactorBinding | undefined>();
		expect(readMfaStoreFactor({ ...FULL_WIRE, binding: "federated" })).toStrictEqual({
			...FULL_WIRE,
			binding: "federated",
		});
	});

	it("carries times as epoch milliseconds named …Ms", () => {
		expect(toMfaStoreFactor(FULL)).toStrictEqual(FULL_WIRE);
	});

	it("leaves an optional field with no value out, never null", () => {
		const wire = toMfaStoreFactor(BARE);
		expect(Object.keys(wire).sort()).toEqual(
			["createdAtMs", "data", "id", "kind", "subject", "version"].sort(),
		);
		expect(JSON.stringify(wire)).not.toContain("null");
	});

	it("round-trips every record through JSON, its undefined fields named again", () => {
		for (const record of [FULL, BARE]) {
			const read = readMfaStoreFactor(overJson(toMfaStoreFactor(record)));
			expect(read).toBeDefined();
			expect(fromMfaStoreFactor(read as MfaStoreFactor)).toStrictEqual(record);
		}
	});

	it("round-trips every binding, a contributed kind, data byte for byte, and the version's bounds", () => {
		const records: MfaFactorRecord[] = [
			{ ...FULL, binding: "email_proof", kind: "email" },
			{ ...FULL, binding: "federated", kind: "webauthn" },
			{ ...FULL, binding: "mfa", kind: "acme-contributed" },
			{ ...FULL, data: '{"a":[],"b":{}} ü∆ 漢字 🙂' },
			{ ...FULL, version: 0 },
			{ ...FULL, version: Number.MAX_SAFE_INTEGER },
			{ ...FULL, createdAt: new Date(-8.64e15), lastUsedAt: new Date(8.64e15) },
		];
		for (const record of records) {
			const read = readMfaStoreFactor(overJson(toMfaStoreFactor(record)));
			expect(fromMfaStoreFactor(read as MfaStoreFactor)).toStrictEqual(record);
		}
	});

	it("reads a record into a fresh object of its own fields, ignoring any other", () => {
		const read = readMfaStoreFactor({ ...FULL_WIRE, storeNote: "kept by the Store" });
		expect(read).toStrictEqual(FULL_WIRE);
	});

	it("refuses to read null for an optional field: null is a value, not unset", () => {
		for (const field of ["label", "binding", "lastUsedAtMs"] as const) {
			expect(readMfaStoreFactor({ ...FULL_WIRE, [field]: null }), field).toBeUndefined();
		}
	});

	it("refuses to read a record missing a required field, or carrying one of the wrong type", () => {
		for (const field of ["id", "subject", "kind", "createdAtMs", "version", "data"] as const) {
			const { [field]: _dropped, ...missing } = FULL_WIRE;
			expect(readMfaStoreFactor(missing), `${field} missing`).toBeUndefined();
			expect(readMfaStoreFactor({ ...FULL_WIRE, [field]: null }), `${field} null`).toBeUndefined();
		}
		for (const [field, value] of [
			["id", 1],
			["subject", {}],
			["kind", ["totp"]],
			["label", 7],
			["binding", "sms"],
			["createdAtMs", "1756684800000"],
			["createdAtMs", 1.5],
			["createdAtMs", 8.64e15 + 1],
			["createdAtMs", Number.NaN],
			["lastUsedAtMs", -8.64e15 - 1],
			["version", -1],
			["version", 1.5],
			["version", Number.MAX_SAFE_INTEGER + 1],
			["version", "3"],
			["data", { sealed: true }],
		] as const) {
			expect(readMfaStoreFactor({ ...FULL_WIRE, [field]: value }), `${field}: ${value}`).toBe(
				undefined,
			);
		}
	});

	it("refuses to read anything but an object holding the fields as its own", () => {
		for (const value of [undefined, null, "record", 1, [], [FULL_WIRE]]) {
			expect(readMfaStoreFactor(value)).toBeUndefined();
		}
		expect(readMfaStoreFactor(Object.create(FULL_WIRE))).toBeUndefined();
	});

	it("refuses, with a RangeError, to write a record the reader would not read back", () => {
		for (const [what, record] of [
			["an invalid createdAt", { ...FULL, createdAt: new Date(Number.NaN) }],
			["a createdAt that is no Date", { ...FULL, createdAt: "2026-09-01" }],
			["a lastUsedAt past the Date range", { ...FULL, lastUsedAt: new Date(8.64e15 + 1) }],
			["a negative version", { ...FULL, version: -1 }],
			["a fractional version", { ...FULL, version: 1.5 }],
			["a binding the record does not admit", { ...FULL, binding: "sms" }],
			["a label that is no string", { ...FULL, label: 7 }],
			["data that is no string", { ...FULL, data: { sealed: true } }],
			["an id that is no string", { ...FULL, id: 1 }],
		] as const) {
			expect(() => toMfaStoreFactor(record as unknown as MfaFactorRecord), what).toThrow(
				RangeError,
			);
		}
	});
});

/** One character of each code point given. */
const chars = (...codes: number[]): string => String.fromCodePoint(...codes);

describe("the fields a page shows", () => {
	it("reads an id of 22 base64url characters, a kind of the hint grammar, and a label of 1 to 64 printable characters", () => {
		for (const [field, value] of [
			["id", "AAAAAAAAAAAAAAAAAAAAAA"],
			["id", "-_-_-_-_-_-_-_-_-_-_-_"],
			["kind", "totp"],
			["kind", "recovery_code"],
			["kind", `a${"b".repeat(63)}`],
			["label", "x"],
			["label", "L".repeat(64)],
			["label", "Téléphone de travail"],
			["label", chars(0x1f642).repeat(64)],
			["label", 'tab-free, quotes " and backslash \\'],
		] as const) {
			expect(
				readMfaStoreFactor({ ...FULL_WIRE, [field]: value }),
				`${field}: ${value}`,
			).toBeDefined();
		}
	});

	it("refuses to read an id that is not 22 base64url characters", () => {
		for (const id of [
			"",
			"factor-1",
			"A".repeat(21),
			"A".repeat(23),
			`${"A".repeat(21)}+`,
			`${"A".repeat(21)}/`,
			`${"A".repeat(20)}==`,
			`${"A".repeat(21)} `,
		]) {
			expect(readMfaStoreFactor({ ...FULL_WIRE, id }), JSON.stringify(id)).toBeUndefined();
		}
	});

	it("refuses to read a kind outside the hint grammar", () => {
		for (const kind of ["", "TOTP", "1totp", "totp code", "tötp", `a${"b".repeat(64)}`, "-totp"]) {
			expect(readMfaStoreFactor({ ...FULL_WIRE, kind }), JSON.stringify(kind)).toBeUndefined();
		}
	});

	it("refuses to read a label that is empty, longer than 64 characters, or not printable on one line", () => {
		for (const [what, label] of [
			["empty", ""],
			["65 characters", "L".repeat(65)],
			["a million characters", "L".repeat(1_000_000)],
			["a line break", "a\r\nb"],
			["NUL", `a${chars(0)}b`],
			["ESC", `a${chars(0x1b)}[31mb`],
			["a tab", `a${chars(9)}b`],
			["DEL", `a${chars(0x7f)}b`],
			["a C1 control", `a${chars(0x85)}b`],
			["a line separator", `a${chars(0x2028)}b`],
			["a bidi override", `a${chars(0x202e)}b`],
			["a directional mark", `a${chars(0x200f)}b`],
			["a lone surrogate", `a${String.fromCharCode(0xd800)}b`],
		] as const) {
			expect(readMfaStoreFactor({ ...FULL_WIRE, label }), what).toBeUndefined();
		}
	});

	it("refuses, with a RangeError, to write an id, a kind or a label the reader would refuse", () => {
		for (const [what, record] of [
			["an id not of D7's shape", { ...FULL, id: "factor-1" }],
			["a kind outside the grammar", { ...FULL, kind: "TOTP" }],
			["a label over 64 characters", { ...FULL, label: "L".repeat(65) }],
			["a label with a line break", { ...FULL, label: "a\nb" }],
		] as const) {
			expect(() => toMfaStoreFactor(record), what).toThrow(RangeError);
		}
		expect(() =>
			toMfaStoreFactorChanges({ data: "v2.x", label: "", lastUsedAt: undefined }),
		).toThrow(RangeError);
		expect(() =>
			toMfaStoreUpdateRequest("user-1", "factor-1", 1, {
				data: "v2.x",
				label: undefined,
				lastUsedAt: undefined,
			}),
		).toThrow(RangeError);
	});
});

describe("a list answer", () => {
	const SECOND = { ...FULL_WIRE, id: ID_2, kind: "email" };

	it("reads every record of the subject asked for, each a fresh object of its own fields", () => {
		const reading = readMfaStoreListAnswer(
			overJson({ factors: [{ ...FULL_WIRE, storeNote: "x" }, SECOND] }),
			"user-1",
		);
		expect(reading).toStrictEqual({ ok: true, factors: [FULL_WIRE, SECOND] });
		expect(readMfaStoreListAnswer({ factors: [] }, "user-1")).toStrictEqual({
			ok: true,
			factors: [],
		});
	});

	it("is malformed when it is not { factors: [...] }", () => {
		for (const value of [undefined, null, [], "factors", {}, { factors: null }, { factors: {} }]) {
			expect(readMfaStoreListAnswer(value, "user-1"), JSON.stringify(value)).toStrictEqual({
				ok: false,
				reason: "malformed",
			});
		}
	});

	it("is unreadable, whole, when one record is unreadable, names another subject, or repeats an id", () => {
		for (const [what, factors] of [
			["an unreadable record", [FULL_WIRE, { ...SECOND, label: null }]],
			["a record of another subject", [FULL_WIRE, { ...SECOND, subject: "user-2" }]],
			["two records with one id", [FULL_WIRE, { ...SECOND, id: ID_1 }]],
			["a record that is no object", [FULL_WIRE, "record"]],
		] as const) {
			expect(readMfaStoreListAnswer({ factors }, "user-1"), what).toStrictEqual({
				ok: false,
				reason: "unreadable",
			});
		}
	});
});

describe("an update on the wire", () => {
	const next: MfaFactorRecordUpdate = {
		data: "v2.re-sealed",
		label: "Work phone",
		lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
	};

	it("names the record by subject and id, and carries the expected version and, as its changes, only data, label and lastUsedAtMs", () => {
		expect(toMfaStoreUpdateRequest("user-1", ID_1, 3, next)).toStrictEqual({
			subject: "user-1",
			id: ID_1,
			expectedVersion: 3,
			changes: {
				data: "v2.re-sealed",
				label: "Work phone",
				lastUsedAtMs: Date.parse("2026-09-03T00:00:00.000Z"),
			},
		});
		expectTypeOf<keyof MfaStoreFactorChanges>().toEqualTypeOf<"data" | "label" | "lastUsedAtMs">();
		expectTypeOf<keyof MfaStoreUpdateRequest>().toEqualTypeOf<
			"subject" | "id" | "expectedVersion" | "changes"
		>();
	});

	it("copies only the three fields, even from a whole record handed in as the update", () => {
		expect(toMfaStoreFactorChanges(FULL)).toStrictEqual({
			data: FULL.data,
			label: FULL.label,
			lastUsedAtMs: FULL.lastUsedAt?.getTime(),
		});
	});

	it("leaves out a label and a lastUsedAtMs the update clears, never null", () => {
		const cleared = toMfaStoreFactorChanges({
			data: "v2.x",
			label: undefined,
			lastUsedAt: undefined,
		});
		expect(cleared).toStrictEqual({ data: "v2.x" });
		expect(readMfaStoreFactorChanges(overJson(cleared))).toStrictEqual({ data: "v2.x" });
	});

	it("round-trips the changes through JSON", () => {
		const changes = toMfaStoreFactorChanges(next);
		expect(readMfaStoreFactorChanges(overJson(changes))).toStrictEqual(changes);
	});

	it("refuses to read changes that carry any field but the three, or null for one", () => {
		const changes = toMfaStoreFactorChanges(next);
		for (const field of ["id", "subject", "kind", "binding", "createdAtMs", "version", "note"]) {
			expect(readMfaStoreFactorChanges({ ...changes, [field]: "x" }), field).toBeUndefined();
		}
		for (const text of [
			'{"data":"x","__proto__":{"subject":"victim"}}',
			'{"data":"x","constructor":{"prototype":{}}}',
		]) {
			expect(readMfaStoreFactorChanges(JSON.parse(text)), text).toBeUndefined();
		}
		for (const field of ["label", "lastUsedAtMs", "data"]) {
			expect(readMfaStoreFactorChanges({ ...changes, [field]: null }), field).toBeUndefined();
		}
		for (const value of [undefined, null, "changes", [], { label: "no data" }]) {
			expect(readMfaStoreFactorChanges(value)).toBeUndefined();
		}
	});

	it("refuses, with a RangeError, an update whose version cannot advance or is no version", () => {
		for (const expectedVersion of [Number.MAX_SAFE_INTEGER, -1, 1.5, Number.NaN]) {
			expect(
				() => toMfaStoreUpdateRequest("user-1", ID_1, expectedVersion, next),
				String(expectedVersion),
			).toThrow(RangeError);
		}
		expect(() =>
			toMfaStoreUpdateRequest("user-1", ID_1, 1, {
				...next,
				lastUsedAt: new Date(Number.NaN),
			}),
		).toThrow(RangeError);
	});
});

/** Generations as a Store issues them: opaque, 1 to 128 visible ASCII characters, none of them `"`. */
const GENERATION = "6f1d2c3b-4a59-4e8f-9d7c-0b1a2c3d4e5f" as StoreGeneration;
const NEXT_GENERATION = "c0ffee-2" as StoreGeneration;

/** Values no Store may answer, nor a caller hand back, as a generation. */
const NOT_GENERATIONS: readonly unknown[] = [
	"",
	'a"b',
	'"6f1d2c3b"',
	"with space",
	"x".repeat(129),
	"généré",
	"tab\there",
	7,
	true,
	{},
];

describe("a versioned list answer", () => {
	const SECOND = { ...FULL_WIRE, id: ID_2, kind: "email" };

	it("reads factors and generation into the port's set: items as records, and the generation", () => {
		const set = readMfaStoreVersionedListAnswer(
			overJson({ factors: [{ ...FULL_WIRE, storeNote: "x" }, SECOND], generation: GENERATION }),
			"user-1",
		);
		expect(set).toStrictEqual({
			items: [fromMfaStoreFactor(FULL_WIRE), fromMfaStoreFactor(SECOND)],
			generation: GENERATION,
		});
		expect(Object.isFrozen(set)).toBe(true);
		expect(Object.isFrozen(set.items)).toBe(true);
		expect(set.items.every((record) => Object.isFrozen(record))).toBe(true);
	});

	it("reads an absent set as a 200 stating it: no factors and a null generation", () => {
		expect(
			readMfaStoreVersionedListAnswer(overJson({ factors: [], generation: null }), "user-1"),
		).toStrictEqual({ items: [], generation: null });
	});

	it("reads an emptied set, whose tombstone stands, as no factors at its generation", () => {
		expect(
			readMfaStoreVersionedListAnswer({ factors: [], generation: GENERATION }, "user-1"),
		).toStrictEqual({ items: [], generation: GENERATION });
	});

	it("throws a TypeError for an answer that is not { factors: [...], generation }", () => {
		for (const value of [
			undefined,
			null,
			[],
			"factors",
			{},
			{ factors: [] },
			{ generation: GENERATION },
			{ factors: null, generation: GENERATION },
			{ factors: {}, generation: GENERATION },
			{ factors: [], generation: undefined },
		]) {
			expect(() => readMfaStoreVersionedListAnswer(value, "user-1"), String(value)).toThrow(
				TypeError,
			);
		}
	});

	it("throws a TypeError for a generation that is no store generation, one holding a quote included", () => {
		for (const generation of NOT_GENERATIONS) {
			expect(
				() => readMfaStoreVersionedListAnswer({ factors: [], generation }, "user-1"),
				String(generation),
			).toThrow(TypeError);
		}
	});

	it("throws a TypeError for factors held by an absent set", () => {
		expect(() =>
			readMfaStoreVersionedListAnswer({ factors: [FULL_WIRE], generation: null }, "user-1"),
		).toThrow(TypeError);
	});

	it("throws a TypeError, whole, when one record is unreadable, names another subject, or repeats an id", () => {
		for (const [what, factors] of [
			["an unreadable record", [FULL_WIRE, { ...SECOND, label: null }]],
			["a record of another subject", [FULL_WIRE, { ...SECOND, subject: "user-2" }]],
			["two records with one id", [FULL_WIRE, { ...SECOND, id: ID_1 }]],
			["a record that is no object", [FULL_WIRE, "record"]],
		] as const) {
			expect(
				() => readMfaStoreVersionedListAnswer({ factors, generation: GENERATION }, "user-1"),
				what,
			).toThrow(TypeError);
		}
	});

	it("throws a TypeError, never another error, for a field whose read throws", () => {
		const throwing = {
			get factors(): never {
				throw new Error("read");
			},
			generation: GENERATION,
		};
		const record = {
			...FULL_WIRE,
			get data(): never {
				throw new Error("read");
			},
		};
		expect(() => readMfaStoreVersionedListAnswer(throwing, "user-1")).toThrow(TypeError);
		expect(() =>
			readMfaStoreVersionedListAnswer({ factors: [record], generation: GENERATION }, "user-1"),
		).toThrow(TypeError);
	});

	it("leaves the plain list answer as it was: it reads the same answer and ignores the generation", () => {
		expect(
			readMfaStoreListAnswer({ factors: [FULL_WIRE], generation: GENERATION }, "user-1"),
		).toStrictEqual({ ok: true, factors: [FULL_WIRE] });
	});
});

describe("a conditional create on the wire", () => {
	it("carries the factor, the generation the writer read as expectedGeneration, and the deadline as deadlineMs", () => {
		expect(toMfaStoreCreateIfRequest(FULL, GENERATION, DEADLINE_MS)).toStrictEqual({
			factor: FULL_WIRE,
			expectedGeneration: GENERATION,
			deadlineMs: DEADLINE_MS,
		});
		expectTypeOf<keyof MfaStoreCreateIfRequest>().toEqualTypeOf<
			"factor" | "expectedGeneration" | "deadlineMs"
		>();
		expectTypeOf<MfaStoreCreateIfRequest["deadlineMs"]>().toEqualTypeOf<number>();
	});

	it("carries null, present and never left out, for a set the writer read as absent", () => {
		const request = toMfaStoreCreateIfRequest(BARE, null, DEADLINE_MS);
		expect(request).toStrictEqual({
			factor: toMfaStoreFactor(BARE),
			expectedGeneration: null,
			deadlineMs: DEADLINE_MS,
		});
		expect(overJson(request)).toHaveProperty("expectedGeneration", null);
		expect(overJson(request)).toHaveProperty("deadlineMs", DEADLINE_MS);
	});

	it("takes the deadline as a required parameter: no caller can leave it out", () => {
		expectTypeOf(toMfaStoreCreateIfRequest).parameters.toEqualTypeOf<
			[MfaFactorRecord, StoreGeneration | null, number]
		>();
		// @ts-expect-error -- a conditional create always carries a deadline.
		expect(() => toMfaStoreCreateIfRequest(FULL, GENERATION)).toThrow(RangeError);
	});

	it("refuses, with a RangeError, a deadline that is not a whole instant above 0 within the Date range", () => {
		for (const deadline of NOT_DEADLINES) {
			expect(
				() => toMfaStoreCreateIfRequest(FULL, GENERATION, deadline as number),
				String(deadline),
			).toThrow(RangeError);
		}
		expect(toMfaStoreCreateIfRequest(FULL, GENERATION, 1)).toHaveProperty("deadlineMs", 1);
		expect(toMfaStoreCreateIfRequest(FULL, GENERATION, MAX_STORABLE_EXPIRY_MS)).toHaveProperty(
			"deadlineMs",
			MAX_STORABLE_EXPIRY_MS,
		);
	});

	it("refuses, with a RangeError, an expected generation that is no store generation, or none", () => {
		for (const expected of [...NOT_GENERATIONS, undefined]) {
			expect(
				() => toMfaStoreCreateIfRequest(FULL, expected as StoreGeneration, DEADLINE_MS),
				String(expected),
			).toThrow(RangeError);
		}
	});

	it("refuses, with a RangeError, a record the factor reader would not read back", () => {
		expect(() =>
			toMfaStoreCreateIfRequest({ ...FULL, id: "short" }, GENERATION, DEADLINE_MS),
		).toThrow(RangeError);
	});

	it("reads a 200 as created, with the set's new generation, and a 409 as a conflict", () => {
		expect(
			readMfaStoreCreateIfAnswer(200, { outcome: "created", generation: NEXT_GENERATION }),
		).toStrictEqual({ outcome: "created", generation: NEXT_GENERATION });
		expect(readMfaStoreCreateIfAnswer(409, { outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("throws a TypeError for a 409 or a 200 without its body: a bare status may be a misrouted request or an older Store", () => {
		for (const status of [200, 409]) {
			for (const body of [undefined, null, "", {}]) {
				expect(() => readMfaStoreCreateIfAnswer(status, body), `${status} ${String(body)}`).toThrow(
					TypeError,
				);
			}
		}
	});

	it("throws a TypeError for a body whose outcome is not its status's, or a created one with no generation", () => {
		for (const [status, body] of [
			[200, { outcome: "conflict" }],
			[409, { outcome: "created", generation: NEXT_GENERATION }],
			[200, { outcome: "created" }],
			[200, { generation: NEXT_GENERATION }],
			[200, { outcome: "updated", generation: NEXT_GENERATION }],
		] as const) {
			expect(() => readMfaStoreCreateIfAnswer(status, body), JSON.stringify(body)).toThrow(
				TypeError,
			);
		}
		for (const generation of NOT_GENERATIONS) {
			expect(
				() => readMfaStoreCreateIfAnswer(200, { outcome: "created", generation }),
				String(generation),
			).toThrow(TypeError);
		}
	});

	it("throws a TypeError for a 408, whatever its body: a Store that read the request past its deadline wrote nothing, and that is no outcome", () => {
		for (const body of [
			undefined,
			{},
			{ outcome: "created", generation: NEXT_GENERATION },
			{ outcome: "conflict" },
		]) {
			expect(() => readMfaStoreCreateIfAnswer(408, body), JSON.stringify(body)).toThrow(TypeError);
		}
	});

	it("throws a TypeError for any other status, a 404 included: a create is never missing", () => {
		for (const [status, body] of [
			[404, { outcome: "missing" }],
			[404, { outcome: "conflict" }],
			[201, { outcome: "created", generation: NEXT_GENERATION }],
			[204, undefined],
			[400, { outcome: "conflict" }],
			[412, { outcome: "conflict" }],
			[500, undefined],
		] as const) {
			expect(() => readMfaStoreCreateIfAnswer(status, body), String(status)).toThrow(TypeError);
		}
	});
});

describe("a conditional remove on the wire", () => {
	it("names the record by subject and id, and carries the generation the writer read as expectedGeneration and the deadline as deadlineMs", () => {
		const request = toMfaStoreRemoveIfRequest("user-1", ID_1, GENERATION, DEADLINE_MS);
		expect(request).toStrictEqual({
			subject: "user-1",
			id: ID_1,
			expectedGeneration: GENERATION,
			deadlineMs: DEADLINE_MS,
		});
		expect(overJson(request)).toHaveProperty("deadlineMs", DEADLINE_MS);
		expectTypeOf<keyof MfaStoreRemoveIfRequest>().toEqualTypeOf<
			"subject" | "id" | "expectedGeneration" | "deadlineMs"
		>();
		expectTypeOf<MfaStoreRemoveIfRequest["deadlineMs"]>().toEqualTypeOf<number>();
	});

	it("names only the reset as the delete request without a generation", () => {
		expectTypeOf<keyof MfaStoreDeleteRequest>().toEqualTypeOf<"subject" | "all">();
		expectTypeOf<MfaStoreDeleteRequest["all"]>().toEqualTypeOf<true>();
	});

	it("takes the deadline as a required parameter: no caller can leave it out", () => {
		expectTypeOf(toMfaStoreRemoveIfRequest).parameters.toEqualTypeOf<
			[string, string, StoreGeneration, number]
		>();
		// @ts-expect-error -- a conditional remove always carries a deadline.
		expect(() => toMfaStoreRemoveIfRequest("user-1", ID_1, GENERATION)).toThrow(RangeError);
	});

	it("refuses, with a RangeError, a deadline that is not a whole instant above 0 within the Date range", () => {
		for (const deadline of NOT_DEADLINES) {
			expect(
				() => toMfaStoreRemoveIfRequest("user-1", ID_1, GENERATION, deadline as number),
				String(deadline),
			).toThrow(RangeError);
		}
		expect(toMfaStoreRemoveIfRequest("user-1", ID_1, GENERATION, 1)).toHaveProperty(
			"deadlineMs",
			1,
		);
		expect(
			toMfaStoreRemoveIfRequest("user-1", ID_1, GENERATION, MAX_STORABLE_EXPIRY_MS),
		).toHaveProperty("deadlineMs", MAX_STORABLE_EXPIRY_MS);
	});

	it("refuses, with a RangeError, an expected generation that is no store generation, null included", () => {
		for (const expected of [...NOT_GENERATIONS, null, undefined]) {
			expect(
				() => toMfaStoreRemoveIfRequest("user-1", ID_1, expected as StoreGeneration, DEADLINE_MS),
				String(expected),
			).toThrow(RangeError);
		}
	});

	it("refuses, with a RangeError, an id no record can have, or a subject that is no string", () => {
		expect(() => toMfaStoreRemoveIfRequest("user-1", "short", GENERATION, DEADLINE_MS)).toThrow(
			RangeError,
		);
		expect(() =>
			toMfaStoreRemoveIfRequest(7 as unknown as string, ID_1, GENERATION, DEADLINE_MS),
		).toThrow(RangeError);
	});

	it("reads a 200 as removed, with the set's new generation, a 404 as missing, and a 409 as a conflict", () => {
		expect(
			readMfaStoreRemoveIfAnswer(200, { outcome: "removed", generation: NEXT_GENERATION }),
		).toStrictEqual({ outcome: "removed", generation: NEXT_GENERATION });
		expect(readMfaStoreRemoveIfAnswer(404, { outcome: "missing" })).toStrictEqual({
			outcome: "missing",
		});
		expect(readMfaStoreRemoveIfAnswer(409, { outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("throws a TypeError for a 404, a 409 or a 200 without its body", () => {
		for (const status of [200, 404, 409]) {
			for (const body of [undefined, null, "", {}]) {
				expect(() => readMfaStoreRemoveIfAnswer(status, body), `${status} ${String(body)}`).toThrow(
					TypeError,
				);
			}
		}
	});

	it("throws a TypeError for a body whose outcome is not its status's, or a removed one with no generation", () => {
		for (const [status, body] of [
			[404, { outcome: "conflict" }],
			[409, { outcome: "missing" }],
			[200, { outcome: "missing" }],
			[404, { outcome: "removed", generation: NEXT_GENERATION }],
			[200, { outcome: "removed" }],
			[200, { generation: NEXT_GENERATION }],
		] as const) {
			expect(
				() => readMfaStoreRemoveIfAnswer(status, body),
				`${status} ${JSON.stringify(body)}`,
			).toThrow(TypeError);
		}
		for (const generation of NOT_GENERATIONS) {
			expect(
				() => readMfaStoreRemoveIfAnswer(200, { outcome: "removed", generation }),
				String(generation),
			).toThrow(TypeError);
		}
	});

	it("throws a TypeError for a 408, whatever its body: a Store that read the request past its deadline wrote nothing, and that is no outcome", () => {
		for (const body of [
			undefined,
			{},
			{ outcome: "removed", generation: NEXT_GENERATION },
			{ outcome: "missing" },
			{ outcome: "conflict" },
		]) {
			expect(() => readMfaStoreRemoveIfAnswer(408, body), JSON.stringify(body)).toThrow(TypeError);
		}
	});

	it("throws a TypeError for any other status", () => {
		for (const [status, body] of [
			[204, undefined],
			[202, { outcome: "removed", generation: NEXT_GENERATION }],
			[400, { outcome: "conflict" }],
			[412, { outcome: "conflict" }],
			[503, undefined],
		] as const) {
			expect(() => readMfaStoreRemoveIfAnswer(status, body), String(status)).toThrow(TypeError);
		}
	});
});
