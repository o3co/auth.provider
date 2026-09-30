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
 * read as "unset". What a writer makes, the reader reads back whole; what the
 * reader would refuse, the writer refuses with a `RangeError`. An update
 * sends the expected version and `data`, `label` and `lastUsedAtMs`, nothing
 * else of the record.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { MfaFactorRecord, MfaFactorRecordUpdate } from "#/mfa/factorStore.mjs";
import {
	fromMfaStoreFactor,
	type MfaStoreFactor,
	type MfaStoreFactorChanges,
	type MfaStoreUpdateRequest,
	readMfaStoreFactor,
	readMfaStoreFactorChanges,
	toMfaStoreFactor,
	toMfaStoreFactorChanges,
	toMfaStoreUpdateRequest,
} from "#/mfa/storeWire.mjs";

const FULL: MfaFactorRecord = {
	id: "factor-1",
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
	id: "factor-2",
	label: undefined,
	binding: undefined,
	lastUsedAt: undefined,
};

const FULL_WIRE: MfaStoreFactor = {
	id: "factor-1",
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAtMs: Date.parse("2026-09-01T00:00:00.000Z"),
	lastUsedAtMs: Date.parse("2026-09-02T00:00:00.000Z"),
	version: 3,
	data: "v2.opaque-sealed-data",
};

/** `value` as it arrives after a trip through JSON. */
const overJson = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

describe("a factor record on the wire", () => {
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

	it("round-trips every binding, any kind, data byte for byte, and the version's bounds", () => {
		const records: MfaFactorRecord[] = [
			{ ...FULL, binding: "email_proof", kind: "email" },
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

describe("an update on the wire", () => {
	const next: MfaFactorRecordUpdate = {
		data: "v2.re-sealed",
		label: "Work phone",
		lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
	};

	it("sends the expected version and data, label and lastUsedAtMs, nothing else of the record", () => {
		expect(toMfaStoreUpdateRequest("user-1", "factor-1", 3, next)).toStrictEqual({
			subject: "user-1",
			id: "factor-1",
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
		for (const field of ["id", "subject", "kind", "binding", "createdAtMs", "version"]) {
			expect(readMfaStoreFactorChanges({ ...changes, [field]: "x" }), field).toBeUndefined();
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
				() => toMfaStoreUpdateRequest("user-1", "factor-1", expectedVersion, next),
				String(expectedVersion),
			).toThrow(RangeError);
		}
		expect(() =>
			toMfaStoreUpdateRequest("user-1", "factor-1", 1, {
				...next,
				lastUsedAt: new Date(Number.NaN),
			}),
		).toThrow(RangeError);
	});
});
