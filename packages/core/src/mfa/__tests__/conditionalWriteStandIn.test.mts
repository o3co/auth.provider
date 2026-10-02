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
 * members are typed by: a store generation, and the readers of a conditional
 * create's and a set's conditional remove's answers. Replaced, with this
 * test, when the convention lands.
 */

import { describe, expect, it } from "vitest";
import {
	isStoreGeneration,
	readConditionalCreateAnswer,
	readConditionalSetRemoveAnswer,
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

	it("throws a RangeError for anything else: never a write that happened, nor one that did not", () => {
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
			expect(() => readConditionalCreateAnswer(answer), JSON.stringify(answer)).toThrow(RangeError);
		}
	});

	it("throws a RangeError, carrying the cause, for an answer whose read throws", () => {
		const cause = new Error("getter");
		const answer = {
			get outcome(): string {
				throw cause;
			},
		};
		expect(() => readConditionalCreateAnswer(answer)).toThrow(
			expect.objectContaining({ name: "RangeError", cause }),
		);
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

	it("throws a RangeError for anything else, a removal with no generation among it", () => {
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
				RangeError,
			);
		}
	});
});
