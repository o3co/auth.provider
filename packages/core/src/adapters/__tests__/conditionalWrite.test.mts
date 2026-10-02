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
 * The conditional-write convention's generations and readers: a generation is
 * 1 to 128 visible ASCII characters; each reader answers a fresh frozen copy
 * of a well-formed answer and refuses anything else with a TypeError, never a
 * value.
 */

import { describe, expect, it } from "vitest";
import {
	BUNDLED_STORE_WRITE_LIFETIME_MS,
	isStoreGeneration,
	newStoreGeneration,
	readConditionalCreateAnswer,
	readConditionalRemoveAnswer,
	readConditionalReplaceAnswer,
	readConditionalSetRemoveAnswer,
	readVersioned,
	readVersionedSet,
	type StoreGeneration,
	type Versioned,
	type VersionedSet,
} from "#/index.mjs";

const G = "7b0c3a52-1d0e-4f43-9a51-2f6a1c9e8d10" as StoreGeneration;

/** Values a generation must never be: empty, too long, outside visible ASCII, not a string. */
const MALFORMED_GENERATIONS: readonly unknown[] = [
	"",
	"a".repeat(129),
	"has space",
	"tab\there",
	"line\n",
	'quote"d',
	'"',
	"nul\u0000",
	"del\u007f",
	"é",
	"\u{1f512}",
	undefined,
	null,
	42,
	{},
	["g"],
];

/** An object whose `key` getter throws. */
const throwingOn = (key: string, rest: Record<string, unknown> = {}): object =>
	Object.defineProperty({ ...rest }, key, {
		enumerable: true,
		get() {
			throw new Error("unreadable");
		},
	});

/** Not an object at all. */
const NOT_OBJECTS: readonly unknown[] = [undefined, "updated", 1, true, Symbol("x")];

describe("BUNDLED_STORE_WRITE_LIFETIME_MS", () => {
	it("is 24 hours, in milliseconds", () => {
		expect(BUNDLED_STORE_WRITE_LIFETIME_MS).toBe(24 * 60 * 60 * 1000);
	});
});

describe("isStoreGeneration", () => {
	it("accepts 1 to 128 visible ASCII characters other than a double quote", () => {
		expect(isStoreGeneration("a")).toBe(true);
		expect(isStoreGeneration("!")).toBe(true);
		expect(isStoreGeneration("~")).toBe(true);
		expect(isStoreGeneration("a".repeat(128))).toBe(true);
		expect(isStoreGeneration(G)).toBe(true);
		expect(isStoreGeneration("#$%&'()*+,-./:;<=>?@[\\]^_`{|}")).toBe(true);
	});

	it("refuses anything else, and never throws", () => {
		for (const value of MALFORMED_GENERATIONS) {
			expect(isStoreGeneration(value), String(value)).toBe(false);
		}
		expect(isStoreGeneration(throwingOn("length"))).toBe(false);
	});
});

describe("newStoreGeneration", () => {
	it("answers a well-formed generation, different on every call", () => {
		const seen = new Set<string>();
		for (let i = 0; i < 1000; i++) {
			const generation = newStoreGeneration();
			expect(isStoreGeneration(generation)).toBe(true);
			seen.add(generation);
		}
		expect(seen.size).toBe(1000);
	});
});

describe("readVersioned", () => {
	it("answers null for null", () => {
		expect(readVersioned(null)).toBeNull();
	});

	it("answers a fresh frozen copy of a well-formed answer, the value as given", () => {
		const value = { a: 1 };
		const answer = { value, generation: G };
		const read = readVersioned(answer);
		expect(read).toStrictEqual({ value, generation: G });
		expect(read).not.toBe(answer);
		expect(Object.isFrozen(read)).toBe(true);
		expect(read?.value).toBe(value);
	});

	it("reads a class instance and a prototype getter as a plain answer would be read", () => {
		class Answer {
			readonly value = "v";
			get generation(): string {
				return G;
			}
		}
		expect(readVersioned(new Answer() as unknown as Versioned<string>)).toStrictEqual({
			value: "v",
			generation: G,
		});
	});

	it("refuses an answer that leaves the value out, and reads one that names it as undefined", () => {
		expect(() => readVersioned({ generation: G } as unknown as Versioned<unknown>)).toThrow(
			TypeError,
		);
		expect(readVersioned({ value: undefined, generation: G })).toStrictEqual({
			value: undefined,
			generation: G,
		});
	});

	it("refuses an answer whose value reads as undefined and whose keys cannot be told, with a TypeError", () => {
		const untellable = new Proxy(
			{ generation: G },
			{
				has() {
					throw new Error("unreadable");
				},
			},
		);
		expect(() => readVersioned(untellable as unknown as Versioned<unknown>)).toThrow(
			new TypeError("versioned read: value could not be read"),
		);
	});

	it("reads each property once", () => {
		let reads = 0;
		const answer = {
			value: "v",
			get generation() {
				reads += 1;
				return reads === 1 ? G : "";
			},
		};
		expect(readVersioned(answer as unknown as Versioned<string>)?.generation).toBe(G);
		expect(reads).toBe(1);
	});

	it("refuses undefined, a non-object, a malformed generation and a throwing read with a TypeError", () => {
		for (const answer of NOT_OBJECTS) {
			expect(() => readVersioned(answer as Versioned<unknown>), String(answer)).toThrow(TypeError);
		}
		for (const generation of MALFORMED_GENERATIONS) {
			expect(
				() => readVersioned({ value: 1, generation } as unknown as Versioned<number>),
				String(generation),
			).toThrow(TypeError);
		}
		expect(() =>
			readVersioned(throwingOn("generation", { value: 1 }) as Versioned<number>),
		).toThrow(TypeError);
		expect(() =>
			readVersioned(throwingOn("value", { generation: G }) as Versioned<number>),
		).toThrow(TypeError);
	});
});

describe("readVersionedSet", () => {
	it("answers a fresh frozen copy, the items in a new frozen array, each item as given", () => {
		const item = { id: "x" };
		const items = [item];
		const answer = { items, generation: G };
		const read = readVersionedSet(answer);
		expect(read).toStrictEqual({ items: [item], generation: G });
		expect(Object.isFrozen(read)).toBe(true);
		expect(Object.isFrozen(read.items)).toBe(true);
		expect(read.items).not.toBe(items);
		expect(read.items[0]).toBe(item);
		items.push({ id: "y" });
		expect(read.items).toHaveLength(1);
	});

	it("answers a null generation only for a set never written, with its items as given", () => {
		expect(readVersionedSet({ items: [], generation: null })).toStrictEqual({
			items: [],
			generation: null,
		});
	});

	it("copies the items with one read of their length and one read of each index, never through an iterator", () => {
		let lengthReads = 0;
		const items = new Proxy(["a", "b"], {
			get(target, key, receiver) {
				if (key === "length") {
					lengthReads += 1;
					return lengthReads === 1 ? 2 : 1;
				}
				if (key === Symbol.iterator) throw new Error("iterated");
				return Reflect.get(target, key, receiver);
			},
		});
		expect(readVersionedSet({ items, generation: G }).items).toEqual(["a", "b"]);
		expect(lengthReads).toBe(1);
	});

	it("refuses items whose length is no whole, non-negative count, with a TypeError", () => {
		for (const length of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "2"]) {
			const items = new Proxy([], {
				get: (target, key, receiver) =>
					key === "length" ? length : Reflect.get(target, key, receiver),
			});
			expect(() => readVersionedSet({ items, generation: G }), String(length)).toThrow(
				new TypeError("versioned set read: items could not be read"),
			);
		}
	});

	it("refuses members with a null generation: null is only an absent set's", () => {
		expect(() => readVersionedSet({ items: [{ id: "x" }], generation: null })).toThrow(TypeError);
	});

	it("refuses undefined where null is meant, a malformed generation, items that are no array, and a throwing read", () => {
		for (const answer of [...NOT_OBJECTS, null]) {
			expect(() => readVersionedSet(answer as VersionedSet<unknown>), String(answer)).toThrow(
				TypeError,
			);
		}
		for (const generation of MALFORMED_GENERATIONS.filter((g) => g !== null)) {
			expect(
				() => readVersionedSet({ items: [], generation } as unknown as VersionedSet<unknown>),
				String(generation),
			).toThrow(TypeError);
		}
		expect(() => readVersionedSet({ generation: G } as unknown as VersionedSet<unknown>)).toThrow(
			TypeError,
		);
		for (const items of [null, undefined, "ab", { length: 1, 0: "a" }, new Set(["a"])]) {
			expect(
				() => readVersionedSet({ items, generation: G } as unknown as VersionedSet<unknown>),
				String(items),
			).toThrow(TypeError);
		}
		expect(() =>
			readVersionedSet(throwingOn("items", { generation: G }) as VersionedSet<unknown>),
		).toThrow(TypeError);
		const unreadableItem = Object.defineProperty([], 0, {
			enumerable: true,
			get() {
				throw new Error("unreadable");
			},
		});
		expect(() => readVersionedSet({ items: unreadableItem, generation: G })).toThrow(TypeError);
	});
});

describe("readConditionalReplaceAnswer", () => {
	it("reads updated with its generation, missing and conflict, as fresh frozen objects", () => {
		const updated = { outcome: "updated", generation: G };
		const read = readConditionalReplaceAnswer(updated);
		expect(read).toStrictEqual({ outcome: "updated", generation: G });
		expect(read).not.toBe(updated);
		expect(Object.isFrozen(read)).toBe(true);
		expect(readConditionalReplaceAnswer({ outcome: "missing" })).toStrictEqual({
			outcome: "missing",
		});
		expect(readConditionalReplaceAnswer({ outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
		expect(Object.isFrozen(readConditionalReplaceAnswer({ outcome: "conflict" }))).toBe(true);
	});

	it("drops what the type does not name", () => {
		expect(
			readConditionalReplaceAnswer({ outcome: "missing", generation: G, extra: 1 }),
		).toStrictEqual({ outcome: "missing" });
	});

	it("refuses another outcome, a missing or malformed generation and a throwing read with a TypeError", () => {
		for (const answer of [
			...NOT_OBJECTS,
			null,
			{},
			{ outcome: "removed" },
			{ outcome: "created", generation: G },
			{ outcome: "UPDATED", generation: G },
			{ outcome: undefined },
			{ outcome: "updated" },
			...MALFORMED_GENERATIONS.map((generation) => ({ outcome: "updated", generation })),
			throwingOn("outcome"),
			throwingOn("generation", { outcome: "updated" }),
		]) {
			expect(() => readConditionalReplaceAnswer(answer), String(answer)).toThrow(TypeError);
		}
	});
});

describe("readConditionalRemoveAnswer", () => {
	it("reads removed, missing and conflict, as fresh frozen objects carrying the outcome alone", () => {
		for (const outcome of ["removed", "missing", "conflict"] as const) {
			const read = readConditionalRemoveAnswer({ outcome, generation: G });
			expect(read).toStrictEqual({ outcome });
			expect(Object.isFrozen(read)).toBe(true);
		}
	});

	it("refuses another outcome and a throwing read with a TypeError", () => {
		for (const answer of [
			...NOT_OBJECTS,
			null,
			{},
			{ outcome: "updated", generation: G },
			{ outcome: "created", generation: G },
			{ outcome: "Removed" },
			throwingOn("outcome"),
		]) {
			expect(() => readConditionalRemoveAnswer(answer), String(answer)).toThrow(TypeError);
		}
	});
});

describe("readConditionalCreateAnswer", () => {
	it("reads created with its generation, and conflict, as fresh frozen objects", () => {
		const read = readConditionalCreateAnswer({ outcome: "created", generation: G });
		expect(read).toStrictEqual({ outcome: "created", generation: G });
		expect(Object.isFrozen(read)).toBe(true);
		expect(readConditionalCreateAnswer({ outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("refuses missing, which a create never answers, another outcome, a missing or malformed generation and a throwing read", () => {
		for (const answer of [
			...NOT_OBJECTS,
			null,
			{},
			{ outcome: "missing" },
			{ outcome: "updated", generation: G },
			{ outcome: "created" },
			...MALFORMED_GENERATIONS.map((generation) => ({ outcome: "created", generation })),
			throwingOn("outcome"),
			throwingOn("generation", { outcome: "created" }),
		]) {
			expect(() => readConditionalCreateAnswer(answer), String(answer)).toThrow(TypeError);
		}
	});
});

describe("readConditionalSetRemoveAnswer", () => {
	it("reads removed with the set's new generation, missing and conflict, as fresh frozen objects", () => {
		const read = readConditionalSetRemoveAnswer({ outcome: "removed", generation: G });
		expect(read).toStrictEqual({ outcome: "removed", generation: G });
		expect(Object.isFrozen(read)).toBe(true);
		expect(readConditionalSetRemoveAnswer({ outcome: "missing" })).toStrictEqual({
			outcome: "missing",
		});
		expect(readConditionalSetRemoveAnswer({ outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("refuses removed without a well-formed generation, another outcome and a throwing read", () => {
		for (const answer of [
			...NOT_OBJECTS,
			null,
			{},
			{ outcome: "removed" },
			...MALFORMED_GENERATIONS.map((generation) => ({ outcome: "removed", generation })),
			{ outcome: "updated", generation: G },
			{ outcome: "created", generation: G },
			throwingOn("outcome"),
			throwingOn("generation", { outcome: "removed" }),
		]) {
			expect(() => readConditionalSetRemoveAnswer(answer), String(answer)).toThrow(TypeError);
		}
	});
});
