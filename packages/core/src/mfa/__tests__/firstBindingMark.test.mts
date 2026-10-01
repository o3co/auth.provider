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
	it("admits a mark noted up to the skew allowance ahead of the store's clock, ending after it", () => {
		expect(() =>
			checkFirstBindingNote("user-1", STORE_NOW, STORE_NOW + MINUTE, STORE_NOW),
		).not.toThrow();
		expect(() =>
			checkFirstBindingNote(
				"user-1",
				STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS,
				STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + MINUTE,
				STORE_NOW,
			),
		).not.toThrow();
	});

	it.each<[string, number, number]>([
		["an end at the store's clock", STORE_NOW - MINUTE, STORE_NOW],
		["an end before the store's clock", STORE_NOW - 2 * MINUTE, STORE_NOW - MINUTE],
		[
			"a time past the skew allowance",
			STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1,
			STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + MINUTE,
		],
	])("refuses %s with a RangeError naming the operation", (_label, atMs, untilMs) => {
		expect(() => checkFirstBindingNote("user-1", atMs, untilMs, STORE_NOW)).toThrow(
			/^MfaTransactionStore\.noteFirstBinding: /,
		);
		expect(() => checkFirstBindingNote("user-1", atMs, untilMs, STORE_NOW)).toThrow(RangeError);
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

describe("laterFirstBindingMark — which of two marks a store keeps", () => {
	const held = { atMs: STORE_NOW - MINUTE, untilMs: STORE_NOW + 10 * MINUTE };

	it("keeps the one noted later, its end with it", () => {
		const next = { atMs: STORE_NOW, untilMs: STORE_NOW + 5 * MINUTE };
		expect(laterFirstBindingMark(held, next)).toStrictEqual(next);
		expect(laterFirstBindingMark(next, held)).toStrictEqual(next);
	});

	it("keeps, of two noted at the same time, the one that ends later", () => {
		const longer = { atMs: held.atMs, untilMs: held.untilMs + MINUTE };
		expect(laterFirstBindingMark(held, longer)).toStrictEqual(longer);
		expect(laterFirstBindingMark(longer, held)).toStrictEqual(longer);
	});

	it("answers a copy of the mark's two fields", () => {
		const kept = laterFirstBindingMark(held, { ...held, extra: 1 } as never);
		expect(kept).toStrictEqual(held);
		expect(kept).not.toBe(held);
	});
});

describe("firstBindingAnswer — what a store answers of a mark it holds", () => {
	const mark = { atMs: STORE_NOW - MINUTE, untilMs: STORE_NOW + 10 * MINUTE };

	it("answers when it was noted while its end is after both the time asked about and the store's clock", () => {
		expect(firstBindingAnswer(mark, STORE_NOW, STORE_NOW)).toBe(STORE_NOW - MINUTE);
	});

	it("answers when it was noted, even after the time asked about", () => {
		expect(firstBindingAnswer(mark, STORE_NOW - 2 * MINUTE, STORE_NOW)).toBe(STORE_NOW - MINUTE);
	});

	it("answers nothing at or past its end, on either clock", () => {
		expect(firstBindingAnswer(mark, mark.untilMs, STORE_NOW)).toBeNull();
		expect(firstBindingAnswer(mark, STORE_NOW, mark.untilMs)).toBeNull();
		expect(firstBindingAnswer(mark, STORE_NOW, mark.untilMs + MINUTE)).toBeNull();
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
