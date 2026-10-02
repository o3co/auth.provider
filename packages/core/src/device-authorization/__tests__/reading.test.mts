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
 * `readDeviceAuthorization`: the one reading of a `DeviceAuthorization` a
 * `DeviceCodeStore` answers, into a plain checked copy or a refusal naming
 * the field.
 */

import { describe, expect, it } from "vitest";
import { readDeviceAuthorization } from "#/device-authorization/reading.mjs";
import type { DeviceAuthorization } from "#/device-authorization/types.mjs";

const NOW = 1_800_000_000_000;

const approved = (): DeviceAuthorization => ({
	userCode: "BCDFGHJK",
	clientId: "tv-app",
	requestedScope: ["openid", "profile"],
	expiresAtMs: NOW + 600_000,
	intervalSeconds: 5,
	status: "approved",
	subject: "user-1",
	grantedScope: ["openid"],
	approvedAtMs: NOW - 1_000,
	amr: ["pwd", "otp", "mfa"],
	authTimeMs: NOW - 60_000,
});

const pending = (): DeviceAuthorization => ({
	userCode: "BCDFGHJK",
	clientId: "tv-app",
	requestedScope: undefined,
	expiresAtMs: NOW + 600_000,
	intervalSeconds: 5,
	status: "pending",
	subject: undefined,
	grantedScope: undefined,
	approvedAtMs: undefined,
	amr: undefined,
	authTimeMs: undefined,
});

/** `record` with `field` replaced by `value`. */
const withField = (record: DeviceAuthorization, field: string, value: unknown): unknown => ({
	...record,
	[field]: value,
});

/** `record` with `field` read through a getter that throws. */
const withThrowingField = (record: DeviceAuthorization, field: string): unknown => {
	const copy: Record<string, unknown> = { ...record };
	Object.defineProperty(copy, field, {
		enumerable: true,
		get() {
			throw new Error(`reading ${field} failed`);
		},
	});
	return copy;
};

/** Every field and values its rule refuses. */
const MALFORMED: ReadonlyArray<readonly [keyof DeviceAuthorization, readonly unknown[]]> = [
	["userCode", [undefined, null, "", 42, ["BCDFGHJK"]]],
	["clientId", [undefined, null, "", 42, { id: "tv-app" }]],
	[
		"requestedScope",
		[
			null,
			"openid",
			[1],
			["openid", null],
			{ 0: "openid", length: 1 },
			[""],
			["openid admin"],
			["openid\tadmin"],
			['"openid"'],
			["open\\id"],
			["openïd"],
		],
	],
	[
		"expiresAtMs",
		[
			undefined,
			null,
			Number.NaN,
			Number.POSITIVE_INFINITY,
			8_640_000_000_000_001,
			"1800000600000",
			new Date(NOW),
		],
	],
	["intervalSeconds", [undefined, null, Number.NaN, -1, Number.POSITIVE_INFINITY, "5"]],
	["status", [undefined, null, "", "APPROVED", "consumed", 1]],
	["subject", [null, "", 42, { sub: "user-1" }]],
	["grantedScope", [null, "openid", [1], [undefined], [""], ["openid admin"], ["openid", " "]]],
	[
		"approvedAtMs",
		[null, Number.NaN, -1, 0.5, 2 ** 53, 8_640_000_000_000_001, "1799999999000", new Date(NOW)],
	],
	[
		"authTimeMs",
		[null, -1, 0.5, Number.NaN, 2 ** 53, 8_640_000_000_000_001, "1799999940000", new Date(NOW)],
	],
];

describe("readDeviceAuthorization", () => {
	it("answers an approved record as a frozen plain copy that shares nothing with it", () => {
		const record = approved();
		const reading = readDeviceAuthorization(record);
		expect(reading).toStrictEqual({ ok: true, authorization: record });
		if (!reading.ok) return;
		const { authorization } = reading;
		expect(authorization).not.toBe(record);
		expect(Object.isFrozen(authorization)).toBe(true);
		for (const field of ["requestedScope", "grantedScope", "amr"] as const) {
			expect(authorization[field], field).not.toBe(record[field]);
			expect(Object.isFrozen(authorization[field]), field).toBe(true);
		}
	});

	it("answers a pending record with every key present, undefined where there is none", () => {
		const reading = readDeviceAuthorization(pending());
		expect(reading).toStrictEqual({ ok: true, authorization: pending() });
		if (!reading.ok) return;
		expect(Object.keys(reading.authorization).sort()).toEqual(Object.keys(approved()).sort());
	});

	it("reads a record however the object holds it: accessors, a class instance, inherited", () => {
		const fields = approved();
		const { clientId, ...rest } = fields;
		class Entity {
			get clientId(): string {
				return clientId;
			}
		}
		const entity = Object.assign(new Entity(), rest);
		const inherited = Object.create(fields) as unknown;
		for (const record of [entity, inherited]) {
			expect(readDeviceAuthorization(record)).toStrictEqual({ ok: true, authorization: fields });
		}
	});

	it("reads each field once", () => {
		const reads = new Map<string, number>();
		const record = new Proxy(approved(), {
			get(target, key, receiver) {
				if (typeof key === "string") reads.set(key, (reads.get(key) ?? 0) + 1);
				return Reflect.get(target, key, receiver);
			},
		});
		expect(readDeviceAuthorization(record).ok).toBe(true);
		expect([...reads.values()].every((count) => count === 1)).toBe(true);
		expect([...reads.keys()].sort()).toEqual(Object.keys(approved()).sort());
	});

	it("refuses what is not an object", () => {
		for (const record of [undefined, null, "record", 42, [approved()], () => approved()]) {
			expect(readDeviceAuthorization(record), String(record)).toStrictEqual({
				ok: false,
				refused: "not_an_object",
			});
		}
	});

	it("refuses a field that does not hold its declared value, naming it", () => {
		for (const [field, values] of MALFORMED) {
			for (const value of values) {
				expect(
					readDeviceAuthorization(withField(approved(), field, value)),
					`${field}: ${String(value)}`,
				).toStrictEqual({ ok: false, refused: "malformed", field });
			}
		}
	});

	it("refuses a field whose read throws, naming it", () => {
		for (const [field] of MALFORMED) {
			expect(readDeviceAuthorization(withThrowingField(approved(), field)), field).toStrictEqual({
				ok: false,
				refused: "malformed",
				field,
			});
		}
	});

	it("refuses a list whose element read throws, naming the field", () => {
		const scope = new Proxy(["openid"], {
			get(target, key, receiver) {
				if (key === "0") throw new Error("element read failed");
				return Reflect.get(target, key, receiver);
			},
		});
		expect(readDeviceAuthorization(withField(approved(), "grantedScope", scope))).toStrictEqual({
			ok: false,
			refused: "malformed",
			field: "grantedScope",
		});
	});

	it("reads a fractional expiry as it is, as a store accepts one", () => {
		const reading = readDeviceAuthorization(withField(approved(), "expiresAtMs", NOW + 0.5));
		expect(reading.ok && reading.authorization.expiresAtMs).toBe(NOW + 0.5);
	});

	it("reads an authentication time as whole epoch milliseconds at or after the epoch that a Date holds", () => {
		for (const authTimeMs of [0, NOW, 8_640_000_000_000_000]) {
			const reading = readDeviceAuthorization(withField(approved(), "authTimeMs", authTimeMs));
			expect(reading.ok && reading.authorization.authTimeMs, String(authTimeMs)).toBe(authTimeMs);
		}
	});

	it("reads an amr it cannot read as none, never a refusal", () => {
		for (const [label, record] of [
			["empty", withField(approved(), "amr", [])],
			["empty entry", withField(approved(), "amr", [""])],
			["not a list", withField(approved(), "amr", "pwd")],
			["null", withField(approved(), "amr", null)],
			["throwing read", withThrowingField(approved(), "amr")],
		] as const) {
			const reading = readDeviceAuthorization(record);
			expect(reading.ok, label).toBe(true);
			expect(reading.ok && reading.authorization.amr).toBeUndefined();
		}
	});
});
