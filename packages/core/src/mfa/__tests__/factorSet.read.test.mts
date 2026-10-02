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
 * `readMfaFactorSet`: what `MfaFactorStore.listVersioned` answered, read as
 * the port promises it, or a `TypeError` the caller answers as the store's
 * outage — never as a set with nothing in it.
 */

import { describe, expect, it } from "vitest";
import { type MfaFactorRecord, readMfaFactorSet } from "#/mfa/factorStore.mjs";

const G = "2b0d5c51-8a4b-4a0e-9a63-0f0c3c1f2f6e";

const record = (id: string, subject = "user-1"): MfaFactorRecord => ({
	id,
	subject,
	kind: "totp",
	label: undefined,
	binding: undefined,
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: undefined,
	version: 1,
	data: "v2.opaque",
});

describe("readMfaFactorSet", () => {
	it("reads a set never written, and a written one with its records, as a fresh answer", () => {
		expect(readMfaFactorSet({ generation: null, items: [] }, "user-1")).toStrictEqual({
			generation: null,
			items: [],
		});
		const items = [
			record("a"),
			{
				...record("b"),
				label: "Phone",
				binding: "mfa" as const,
				lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
			},
		];
		const read = readMfaFactorSet({ generation: G, items, extra: true }, "user-1");
		expect(read).toStrictEqual({ generation: G, items });
		expect(read.items).not.toBe(items);
		expect(Object.isFrozen(read)).toBe(true);
		expect(Object.isFrozen(read.items)).toBe(true);
		for (const [i, copy] of read.items.entries()) {
			expect(copy).not.toBe(items[i]);
			expect(Object.isFrozen(copy)).toBe(true);
		}
		expect(readMfaFactorSet({ generation: G, items: [] }, "user-1")).toStrictEqual({
			generation: G,
			items: [],
		});
	});

	it("throws a TypeError for an answer outside the promise", () => {
		for (const answer of [
			undefined,
			null,
			[],
			{ items: [] },
			{ generation: G },
			{ generation: undefined, items: [] },
			{ generation: "", items: [] },
			{ generation: 1, items: [] },
			{ generation: G, items: {} },
			// A set never written holds nothing.
			{ generation: null, items: [record("a")] },
			// Every record is the subject's, and no id is there twice.
			{ generation: G, items: [record("a", "user-2")] },
			{ generation: G, items: [record("a"), record("a")] },
			{ generation: G, items: [null] },
			{ generation: G, items: [{ ...record("a"), id: 7 }] },
			// A record whole, every field of its type.
			{ generation: G, items: [{ id: "a", subject: "user-1" }] },
			{ generation: G, items: [{ ...record("a"), kind: 1 }] },
			{ generation: G, items: [{ ...record("a"), label: null }] },
			{ generation: G, items: [{ ...record("a"), binding: "other" }] },
			{ generation: G, items: [{ ...record("a"), createdAt: "2026-09-01" }] },
			{ generation: G, items: [{ ...record("a"), createdAt: new Date(Number.NaN) }] },
			{ generation: G, items: [{ ...record("a"), lastUsedAt: 0 }] },
			{ generation: G, items: [{ ...record("a"), version: -1 }] },
			{ generation: G, items: [{ ...record("a"), version: 1.5 }] },
			{ generation: G, items: [{ ...record("a"), data: undefined }] },
		]) {
			expect(() => readMfaFactorSet(answer, "user-1"), JSON.stringify(answer)).toThrow(TypeError);
		}
	});

	it("throws a TypeError for a record that leaves out a key of its type, an optional value's included", () => {
		const keys: readonly (keyof MfaFactorRecord)[] = [
			"id",
			"subject",
			"kind",
			"label",
			"binding",
			"createdAt",
			"lastUsedAt",
			"version",
			"data",
		];
		for (const key of keys) {
			const { [key]: _left, ...rest } = record("a");
			expect(() => readMfaFactorSet({ generation: G, items: [rest] }, "user-1"), key).toThrow(
				TypeError,
			);
			// Inherited is not enough: every key is the record's own.
			const inherited = Object.assign(Object.create({ [key]: record("a")[key] }), rest);
			expect(
				() => readMfaFactorSet({ generation: G, items: [inherited] }, "user-1"),
				`${key} inherited`,
			).toThrow(TypeError);
		}
	});

	it("reads each field of a record once, and checks for a repeated id by the id it read", () => {
		const counted = (ids: readonly string[]) => {
			const reads = new Map<string, number>();
			const source = record("a");
			const item = {};
			for (const key of Object.keys(source) as (keyof MfaFactorRecord)[]) {
				Object.defineProperty(item, key, {
					enumerable: true,
					get: () => {
						const n = reads.get(key) ?? 0;
						reads.set(key, n + 1);
						return key === "id" ? (ids[n] ?? ids.at(-1)) : source[key];
					},
				});
			}
			return { item, reads };
		};
		const one = counted(["a", "b"]);
		const read = readMfaFactorSet({ generation: G, items: [one.item] }, "user-1");
		expect(read.items).toStrictEqual([record("a")]);
		expect([...one.reads.values()].every((n) => n === 1)).toBe(true);
		expect(one.reads.size).toBe(9);
		// Each id reads "a" first and something else after: a second read would miss the repeat.
		const first = counted(["a", "x"]);
		const second = counted(["a", "y"]);
		expect(() =>
			readMfaFactorSet({ generation: G, items: [first.item, second.item] }, "user-1"),
		).toThrow(new TypeError("MfaFactorStore.listVersioned: a record id repeats"));
	});

	it("throws a TypeError for an answer whose read throws, a record's included", () => {
		const answer = {
			get generation(): string {
				throw new RangeError("getter");
			},
			items: [],
		};
		expect(() => readMfaFactorSet(answer, "user-1")).toThrow(TypeError);
		const item = {
			...record("a"),
			get subject(): string {
				throw new RangeError("getter");
			},
		};
		expect(() => readMfaFactorSet({ generation: G, items: [item] }, "user-1")).toThrow(TypeError);
	});
});
