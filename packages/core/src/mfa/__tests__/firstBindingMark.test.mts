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
 * The rules every `MfaTransactionStore` adapter holds a subject's first-binding
 * mark to, in one place: what a note may be, judged on the store's clock,
 * which of two marks is kept, and what a question is answered.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";
import {
	checkFirstBindingNote,
	checkFirstBindingQuestion,
	firstBindingAnswer,
	laterFirstBindingMark,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
} from "#/mfa/transactionStore.mjs";

const STORE_NOW = 1_800_000_000_000;
const MINUTE = 60_000;

describe("checkFirstBindingNote — a mark a store can keep, on its clock", () => {
	it("admits a mark noted within the clock skew allowed either side of the store's clock, ending after it", () => {
		for (const atMs of [
			STORE_NOW,
			STORE_NOW + DEFAULT_CLOCK_SKEW_MS,
			STORE_NOW - DEFAULT_CLOCK_SKEW_MS,
		]) {
			expect(() =>
				checkFirstBindingNote(
					"user-1",
					atMs,
					STORE_NOW + DEFAULT_CLOCK_SKEW_MS + MINUTE,
					STORE_NOW,
				),
			).not.toThrow();
		}
	});

	it.each<[string, number, number]>([
		["an end at the store's clock", STORE_NOW - MINUTE, STORE_NOW],
		["an end before the store's clock", STORE_NOW - 2 * MINUTE, STORE_NOW - MINUTE],
		[
			"a time further ahead than the clock skew allowed",
			STORE_NOW + DEFAULT_CLOCK_SKEW_MS + 1,
			STORE_NOW + DEFAULT_CLOCK_SKEW_MS + MINUTE,
		],
		[
			"a time further behind than the clock skew allowed",
			STORE_NOW - DEFAULT_CLOCK_SKEW_MS - 1,
			STORE_NOW + MINUTE,
		],
	])("refuses %s with a RangeError naming the operation", (_label, atMs, untilMs) => {
		expect(() => checkFirstBindingNote("user-1", atMs, untilMs, STORE_NOW)).toThrow(
			/^MfaTransactionStore\.noteFirstBinding: /,
		);
		expect(() => checkFirstBindingNote("user-1", atMs, untilMs, STORE_NOW)).toThrow(RangeError);
	});

	it("holds a mark to its shape alone when no clock is given, as an adapter whose store judges the clock does", () => {
		expect(() =>
			checkFirstBindingNote("user-1", STORE_NOW - 2 * MINUTE, STORE_NOW - MINUTE),
		).not.toThrow();
		// A day is the longest a mark may stand.
		expect(() =>
			checkFirstBindingNote("user-1", STORE_NOW, STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS),
		).not.toThrow();
		for (const [atMs, untilMs] of [
			[-5, 1],
			[STORE_NOW, 0],
			[STORE_NOW, -1],
			[STORE_NOW - 0.5, STORE_NOW + MINUTE],
			[1e17, 1e17 + 1],
			["x", 1],
			[STORE_NOW, STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1],
		] as const) {
			expect(() => checkFirstBindingNote("user-1", atMs, untilMs), `${atMs} ${untilMs}`).toThrow(
				RangeError,
			);
		}
	});
});

describe("checkFirstBindingQuestion — a question a store can answer", () => {
	it("refuses a time before the epoch, and admits the epoch", () => {
		expect(() => checkFirstBindingQuestion("user-1", -1)).toThrow(RangeError);
		expect(() => checkFirstBindingQuestion("user-1", 0)).not.toThrow();
	});

	it("refuses an empty subject, naming the operation", () => {
		expect(() => checkFirstBindingQuestion("", STORE_NOW)).toThrow(
			/^MfaTransactionStore\.firstBindingAt: /,
		);
	});
});

describe("laterFirstBindingMark — what a store keeps of two marks", () => {
	const held = { atMs: STORE_NOW - MINUTE, untilMs: STORE_NOW + 10 * MINUTE };

	it("keeps the later time and the later end, wherever each comes from", () => {
		const laterShorter = { atMs: STORE_NOW, untilMs: STORE_NOW + 5 * MINUTE };
		const expected = { atMs: STORE_NOW, untilMs: STORE_NOW + 10 * MINUTE };
		expect(laterFirstBindingMark(held, laterShorter)).toStrictEqual(expected);
		expect(laterFirstBindingMark(laterShorter, held)).toStrictEqual(expected);
	});

	it("keeps a mark that is later in both", () => {
		const later = { atMs: STORE_NOW, untilMs: STORE_NOW + 20 * MINUTE };
		expect(laterFirstBindingMark(held, later)).toStrictEqual(later);
		expect(laterFirstBindingMark(later, held)).toStrictEqual(later);
	});

	it("answers a copy of the two fields", () => {
		const kept = laterFirstBindingMark(held, { ...held, extra: 1 } as never);
		expect(kept).toStrictEqual(held);
		expect(kept).not.toBe(held);
	});
});

describe("firstBindingAnswer — what a store answers of a mark it holds", () => {
	const mark = { atMs: STORE_NOW - MINUTE, untilMs: STORE_NOW + 10 * MINUTE };

	it("answers when it was noted while its end is after the store's clock", () => {
		expect(firstBindingAnswer(mark, STORE_NOW)).toBe(STORE_NOW - MINUTE);
		expect(firstBindingAnswer(mark, mark.untilMs - 1)).toBe(STORE_NOW - MINUTE);
	});

	it("answers when it was noted, even when that is after the store's clock", () => {
		expect(firstBindingAnswer(mark, STORE_NOW - 2 * MINUTE)).toBe(STORE_NOW - MINUTE);
	});

	it("answers nothing once the store's clock reaches its end", () => {
		expect(firstBindingAnswer(mark, mark.untilMs)).toBeNull();
		expect(firstBindingAnswer(mark, mark.untilMs + MINUTE)).toBeNull();
	});
});

describe("on the package's root", () => {
	it("are the rules every adapter keeps a mark by", () => {
		expect(core.checkFirstBindingNote).toBe(checkFirstBindingNote);
		expect(core.checkFirstBindingQuestion).toBe(checkFirstBindingQuestion);
		expect(core.laterFirstBindingMark).toBe(laterFirstBindingMark);
		expect(core.firstBindingAnswer).toBe(firstBindingAnswer);
	});
});
