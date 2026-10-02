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
 * The stand-in for core's conditional-write convention that the factor set's
 * members are typed by: a store generation, a versioned set, and the readers
 * of a conditional create's and a set's conditional remove's answers.
 * Replaced, with this test, when the convention lands. A reader throws a
 * `TypeError` for an answer outside its type: the store's fault, where a
 * `RangeError` is the caller's.
 */

import { describe, expect, it } from "vitest";
import {
	isStoreGeneration,
	newStoreGeneration,
	readConditionalCreateAnswer,
	readConditionalSetRemoveAnswer,
	readVersionedSet,
} from "#/mfa/conditionalWriteStandIn.mjs";

const G = "2b0d5c51-8a4b-4a0e-9a63-0f0c3c1f2f6e";

describe("isStoreGeneration", () => {
	it("holds 1 to 128 visible ASCII characters to be a generation", () => {
		expect(isStoreGeneration(G)).toBe(true);
		expect(isStoreGeneration("x")).toBe(true);
		expect(isStoreGeneration("~".repeat(128))).toBe(true);
		expect(isStoreGeneration("!#$%&'()*+,-./:;<=>?@[\\]^_`{|}")).toBe(true);
	});

	it("refuses an empty, an over-long, a spaced or a non-ASCII string, and every non-string", () => {
		for (const value of [
			"",
			"x".repeat(129),
			"a b",
			"a\tb",
			"a\nb",
			"\u007f",
			"é",
			"🙂",
			null,
			undefined,
			1,
			{},
			[G],
			new String(G),
		]) {
			expect(isStoreGeneration(value), String(value)).toBe(false);
		}
	});
});

describe("newStoreGeneration", () => {
	it("makes a store generation, never the same one twice", () => {
		const made = Array.from({ length: 100 }, () => newStoreGeneration());
		for (const generation of made) expect(isStoreGeneration(generation)).toBe(true);
		expect(new Set(made).size).toBe(100);
	});
});

describe("readVersionedSet", () => {
	it("reads a set never written and a written one, its items in a fresh frozen list", () => {
		expect(readVersionedSet({ generation: null, items: [] } as never)).toStrictEqual({
			generation: null,
			items: [],
		});
		const items = [{ id: 1 }, { id: 2 }];
		const read = readVersionedSet({ generation: G, items } as never);
		expect(read).toStrictEqual({ generation: G, items });
		expect(read.items).not.toBe(items);
		expect(read.items[0]).toBe(items[0]);
		expect(Object.isFrozen(read)).toBe(true);
		expect(Object.isFrozen(read.items)).toBe(true);
	});

	it("throws a TypeError for anything else, a generation undefined where null is meant among it", () => {
		for (const answer of [
			undefined,
			null,
			[],
			{ items: [] },
			{ generation: undefined, items: [] },
			{ generation: "", items: [] },
			{ generation: G },
			{ generation: G, items: {} },
		]) {
			expect(() => readVersionedSet(answer as never), JSON.stringify(answer)).toThrow(TypeError);
		}
		const throwing = {
			get items(): unknown[] {
				throw new RangeError("getter");
			},
			generation: G,
		};
		expect(() => readVersionedSet(throwing as never)).toThrow(TypeError);
	});
});

describe("readConditionalCreateAnswer", () => {
	it("reads created with its generation, and conflict, as fresh plain answers", () => {
		const created = { outcome: "created", generation: G, extra: 1 };
		expect(readConditionalCreateAnswer(created)).toStrictEqual({
			outcome: "created",
			generation: G,
		});
		expect(readConditionalCreateAnswer({ outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("throws a TypeError for anything else: never a write that happened, nor one that did not", () => {
		for (const answer of [
			undefined,
			null,
			"created",
			[],
			{},
			{ outcome: "created" },
			{ outcome: "created", generation: "" },
			{ outcome: "created", generation: 7 },
			{ outcome: "updated", generation: G },
			{ outcome: "missing" },
			{ outcome: "removed", generation: G },
		]) {
			expect(() => readConditionalCreateAnswer(answer), JSON.stringify(answer)).toThrow(TypeError);
		}
	});

	it("throws a TypeError for an answer whose read throws, and reads each field once", () => {
		const answer = {
			get outcome(): string {
				throw new RangeError("getter");
			},
		};
		expect(() => readConditionalCreateAnswer(answer)).toThrow(TypeError);
		let reads = 0;
		const counted = {
			get outcome(): string {
				reads += 1;
				return reads === 1 ? "conflict" : "created";
			},
		};
		expect(readConditionalCreateAnswer(counted)).toStrictEqual({ outcome: "conflict" });
		expect(reads).toBe(1);
	});

	it("answers a frozen object", () => {
		expect(Object.isFrozen(readConditionalCreateAnswer({ outcome: "conflict" }))).toBe(true);
		expect(
			Object.isFrozen(readConditionalCreateAnswer({ outcome: "created", generation: G })),
		).toBe(true);
	});
});

describe("readConditionalSetRemoveAnswer", () => {
	it("reads removed with the set's new generation, missing and conflict", () => {
		expect(readConditionalSetRemoveAnswer({ outcome: "removed", generation: G })).toStrictEqual({
			outcome: "removed",
			generation: G,
		});
		expect(readConditionalSetRemoveAnswer({ outcome: "missing" })).toStrictEqual({
			outcome: "missing",
		});
		expect(readConditionalSetRemoveAnswer({ outcome: "conflict" })).toStrictEqual({
			outcome: "conflict",
		});
	});

	it("throws a TypeError for anything else: a set's removal always carries the new generation", () => {
		for (const answer of [
			undefined,
			null,
			{},
			{ outcome: "removed" },
			{ outcome: "removed", generation: null },
			{ outcome: "removed", generation: "a b" },
			{ outcome: "created", generation: G },
			{ outcome: "updated", generation: G },
		]) {
			expect(() => readConditionalSetRemoveAnswer(answer), JSON.stringify(answer)).toThrow(
				TypeError,
			);
		}
	});
});
