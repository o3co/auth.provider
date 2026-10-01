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

import { describe, expect, it } from "vitest";
import {
	judgeHeldUpstreamToken,
	readUpstreamTokenLifetime,
	type UpstreamTokenLifetime,
} from "#/federations/token-lifetime.mjs";

/** When the adapter was asked. */
const CALLED_AT = Date.UTC(2026, 0, 1);
/** When its answer was read: the call took 200 ms. */
const NOW = CALLED_AT + 200;
/** The largest instant a `Date` holds (ECMA-262 §21.4.1.1). */
const MAX_INSTANT_MS = 8.64e15;

const at = (ms: number): Date => new Date(ms);
const read = (expiresIn: unknown, expiresAt: unknown, floorMs = 1000, now = NOW) =>
	readUpstreamTokenLifetime({ expiresIn, expiresAt }, { calledAt: CALLED_AT, now, floorMs });

type Finite = Extract<UpstreamTokenLifetime, { verdict: "finite" }>;
const finite = (reading: UpstreamTokenLifetime): Finite => {
	expect(reading.verdict).toBe("finite");
	return reading as Finite;
};

describe("readUpstreamTokenLifetime — the verdicts", () => {
	it.each([
		["both absent", undefined, undefined],
		["both null", null, null],
		["expiresIn null, expiresAt absent", null, undefined],
		["expiresAt null, expiresIn absent", undefined, null],
	])("%s names no lifetime: unstated", (_, expiresIn, expiresAt) => {
		expect(read(expiresIn, expiresAt)).toEqual({ verdict: "unstated" });
	});

	const future = at(CALLED_AT + 3_600_000);
	it.each([
		["expiresIn NaN", Number.NaN, undefined],
		["expiresIn +Infinity", Number.POSITIVE_INFINITY, undefined],
		["expiresIn -Infinity", Number.NEGATIVE_INFINITY, undefined],
		["expiresIn 0", 0, undefined],
		["expiresIn negative", -5, undefined],
		["expiresIn a numeric string", "3600", undefined],
		["expiresIn a boolean", true, undefined],
		["expiresIn a boxed number", Object(3600), undefined],
		["expiresIn an object", {}, undefined],
		["expiresAt an Invalid Date", undefined, new Date(Number.NaN)],
		["expiresAt an epoch number", undefined, CALLED_AT + 3_600_000],
		["expiresAt an ISO string", undefined, "2026-01-01T01:00:00Z"],
		["expiresAt a Date look-alike", undefined, { getTime: () => CALLED_AT + 3_600_000 }],
		["expiresAt an object that only inherits from Date", undefined, Object.create(Date.prototype)],
		["expiresIn NaN beside a usable expiresAt", Number.NaN, future],
		["expiresAt Invalid beside a usable expiresIn", 3600, new Date(Number.NaN)],
		["expiresIn NaN beside a null expiresAt", Number.NaN, null],
		["expiresAt Invalid beside a null expiresIn", null, new Date(Number.NaN)],
		// Finite seconds whose milliseconds are not.
		["expiresIn that overflows to Infinity in ms", 1e306, undefined],
		["expiresIn that overflows to Infinity in ms, beside a usable expiresAt", 1e306, future],
		// Beyond the Date range: the derived instant, or the anchor it is dated from.
		["expiresIn whose instant leaves the Date range", MAX_INSTANT_MS / 1000, undefined],
		["expiresIn whose anchor leaves the Date range beside a usable expiresAt", 1e13, future],
	])("%s: malformed", (_, expiresIn, expiresAt) => {
		expect(read(expiresIn, expiresAt)).toEqual({ verdict: "malformed" });
	});

	it("never calls into a field: a Date whose getTime is overridden is read by its own value", () => {
		const hostile = new Date(CALLED_AT + 3_600_000);
		hostile.getTime = () => {
			throw new Error("read me");
		};
		expect(finite(read(undefined, hostile)).expiresAt.getTime()).toBe(CALLED_AT + 3_600_000);
	});

	it.each([
		["expiresAt null beside a lifetime", 3600, null],
		["expiresIn null beside an instant", null, at(CALLED_AT + 3_600_000)],
		["expiresIn null beside a past instant", null, at(CALLED_AT - 1)],
	])("%s: contradictory", (_, expiresIn, expiresAt) => {
		expect(read(expiresIn, expiresAt)).toEqual({ verdict: "contradictory" });
	});

	it.each([
		["expiresAt alone, past", undefined, at(CALLED_AT - 1)],
		["expiresAt alone, the epoch", undefined, at(0)],
		["expiresAt past beside a lifetime: the earlier stands", 3600, at(CALLED_AT - 1)],
		["expiresAt the epoch beside a lifetime", 3600, at(0)],
		["expiresIn alone, sub-second", 0.5, undefined],
		["expiresIn alone, ended before the answer was read", 0.1, undefined],
		["expiresAt alone, sub-second left", undefined, at(NOW + 999)],
		["expiresAt sub-second left beside a long lifetime", 3600, at(NOW + 999)],
		["a lifetime of a second, 200 ms of it spent by the call", 1, undefined],
	])("%s: spent under a 1 s floor", (_, expiresIn, expiresAt) => {
		expect(read(expiresIn, expiresAt)).toEqual({ verdict: "spent" });
	});

	it("the floor is inclusive of what it names: exactly floorMs left is finite, a millisecond less spent", () => {
		expect(read(undefined, at(NOW + 1000)).verdict).toBe("finite");
		expect(read(undefined, at(NOW + 999)).verdict).toBe("spent");
		expect(read(undefined, at(NOW + 5000), 5000).verdict).toBe("finite");
		expect(read(undefined, at(NOW + 4999), 5000).verdict).toBe("spent");
	});

	it("under a zero floor a token with any time left is finite, and one with none is spent", () => {
		expect(read(0.5, undefined, 0).verdict).toBe("finite");
		expect(read(undefined, at(NOW + 1), 0).verdict).toBe("finite");
		expect(read(undefined, at(NOW), 0).verdict).toBe("spent");
		expect(read(undefined, at(NOW - 1), 0).verdict).toBe("spent");
		expect(read(3600, at(0), 0).verdict).toBe("spent");
	});

	it("an expiresIn counts from calledAt, not from a late receivedAt", () => {
		// The adapter took 20 s: 10 s of a 30 s token are left, not 30 s.
		const late = CALLED_AT + 20_000;
		const reading = finite(read(30, undefined, 1000, late));
		expect(reading.obtainedAt.getTime()).toBe(CALLED_AT);
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 30_000);
		expect(read(30, undefined, 10_000, late).verdict).toBe("finite");
		expect(read(30, undefined, 10_001, late).verdict).toBe("spent");
	});
});

describe("readUpstreamTokenLifetime — the dating of a finite lifetime", () => {
	it("both fields, the adapter's clock 150 ms ahead of the call: dated from the call", () => {
		const reading = finite(read(3600, at(CALLED_AT + 150 + 3_600_000)));
		expect(reading).toEqual({
			verdict: "finite",
			stated: "both",
			obtainedAt: at(CALLED_AT),
			expiresAt: at(CALLED_AT + 3_600_000),
			issuedLifetime: 3600,
		});
	});

	it("both fields, expiresAt earlier than calledAt + expiresIn: the earlier stands, and the token is dated back", () => {
		const reading = finite(read(3600, at(CALLED_AT + 1_800_000)));
		expect(reading).toEqual({
			verdict: "finite",
			stated: "both",
			obtainedAt: at(CALLED_AT - 1_800_000),
			expiresAt: at(CALLED_AT + 1_800_000),
			issuedLifetime: 3600,
		});
	});

	it("both fields, expiresAt far later than calledAt + expiresIn: it cannot lengthen the lifetime", () => {
		const reading = finite(read(3600, at(MAX_INSTANT_MS)));
		expect(reading.stated).toBe("both");
		expect(reading.obtainedAt.getTime()).toBe(CALLED_AT);
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 3_600_000);
		expect(reading.issuedLifetime).toBe(3600);
	});

	it("expiresIn alone: dated from the call", () => {
		expect(finite(read(3600, undefined))).toEqual({
			verdict: "finite",
			stated: "expiresIn",
			obtainedAt: at(CALLED_AT),
			expiresAt: at(CALLED_AT + 3_600_000),
			issuedLifetime: 3600,
		});
	});

	it("expiresIn alone, fractional: counted to the millisecond", () => {
		const reading = finite(read(1.5, undefined));
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 1500);
		expect(reading.issuedLifetime).toBe(1.5);
	});

	it("expiresAt alone: dated from the call, its lifetime what was left then", () => {
		expect(finite(read(undefined, at(CALLED_AT + 1_800_000)))).toEqual({
			verdict: "finite",
			stated: "expiresAt",
			obtainedAt: at(CALLED_AT),
			expiresAt: at(CALLED_AT + 1_800_000),
			issuedLifetime: 1800,
		});
	});

	it("expiresAt alone at the end of the Date range is finite: a maximum is the consumer's", () => {
		const reading = finite(read(undefined, at(MAX_INSTANT_MS)));
		expect(reading.expiresAt.getTime()).toBe(MAX_INSTANT_MS);
		expect(reading.issuedLifetime).toBe((MAX_INSTANT_MS - CALLED_AT) / 1000);
	});

	it("answers Dates of its own, never the adapter's objects", () => {
		const answered = at(CALLED_AT + 1_800_000);
		const reading = finite(read(undefined, answered));
		expect(reading.expiresAt).not.toBe(answered);
		answered.setTime(0);
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 1_800_000);
	});

	it.each([
		["both, consistent", 3600, at(CALLED_AT + 150 + 3_600_000)],
		["both, the instant earlier", 3600, at(CALLED_AT + 1_800_000)],
		["both, fractional seconds", 7.25, at(CALLED_AT + 7_000)],
		["expiresIn alone", 90, undefined],
		["expiresAt alone", undefined, at(CALLED_AT + 42_000)],
	])(
		"%s: obtainedAt is never after calledAt, and expiresAt is obtainedAt + issuedLifetime to the ms",
		(_, expiresIn, expiresAt) => {
			const reading = finite(read(expiresIn, expiresAt));
			expect(reading.obtainedAt.getTime()).toBeLessThanOrEqual(CALLED_AT);
			expect(reading.issuedLifetime).toBeGreaterThan(0);
			const span = reading.expiresAt.getTime() - reading.obtainedAt.getTime();
			expect(Math.abs(span - reading.issuedLifetime * 1000)).toBeLessThan(1);
		},
	);
});

describe("readUpstreamTokenLifetime — the clock is the consumer's to get right", () => {
	it.each([
		["calledAt NaN", { calledAt: Number.NaN, now: NOW, floorMs: 1000 }],
		["now Infinity", { calledAt: CALLED_AT, now: Number.POSITIVE_INFINITY, floorMs: 1000 }],
		["floorMs negative", { calledAt: CALLED_AT, now: NOW, floorMs: -1 }],
		["floorMs NaN", { calledAt: CALLED_AT, now: NOW, floorMs: Number.NaN }],
		["floorMs Infinity", { calledAt: CALLED_AT, now: NOW, floorMs: Number.POSITIVE_INFINITY }],
	])("%s throws a RangeError", (_, clock) => {
		expect(() =>
			readUpstreamTokenLifetime({ expiresIn: 3600, expiresAt: undefined }, clock),
		).toThrow(RangeError);
	});
});

describe("judgeHeldUpstreamToken — the age of a token already held", () => {
	const OBTAINED = CALLED_AT;
	const LIFETIME_MS = 3_600_000;
	const held = { obtainedAt: at(OBTAINED), expiresAt: at(OBTAINED + LIFETIME_MS) };
	const judge = (now: number, token = held, allowanceMs = 30_000) =>
		judgeHeldUpstreamToken(token, { now, allowanceMs });

	it.each([
		["just obtained", 0, false],
		["a millisecond before the midpoint", LIFETIME_MS / 2 - 1, false],
		["at the midpoint", LIFETIME_MS / 2, true],
		["a millisecond after the midpoint", LIFETIME_MS / 2 + 1, true],
		["at its end", LIFETIME_MS, true],
		["after its end", LIFETIME_MS + 1, true],
	])("%s: halfSpent is %s, and what is left is its end less now", (_, age, halfSpent) => {
		expect(judge(OBTAINED + age)).toEqual({
			believed: true,
			remainingMs: LIFETIME_MS - age,
			halfSpent,
		});
	});

	it("an odd lifetime is half spent at its exact midpoint, between milliseconds", () => {
		const short = { obtainedAt: at(OBTAINED), expiresAt: at(OBTAINED + 5001) };
		expect(judge(OBTAINED + 2500, short).halfSpent).toBe(false);
		expect(judge(OBTAINED + 2501, short).halfSpent).toBe(true);
	});

	it("a lifetime below any refresh buffer is not half spent until its midpoint", () => {
		const fiveSeconds = { obtainedAt: at(OBTAINED), expiresAt: at(OBTAINED + 5000) };
		expect(judge(OBTAINED + 2499, fiveSeconds)).toEqual({
			believed: true,
			remainingMs: 2501,
			halfSpent: false,
		});
		expect(judge(OBTAINED + 2500, fiveSeconds).halfSpent).toBe(true);
	});

	it("dated ahead of now by up to the allowance: believed, never with more left than it was issued with", () => {
		expect(judge(OBTAINED - 30_000)).toEqual({
			believed: true,
			remainingMs: LIFETIME_MS,
			halfSpent: false,
		});
		expect(judge(OBTAINED - 1, held, 0).believed).toBe(false);
		expect(judge(OBTAINED, held, 0).believed).toBe(true);
	});

	const unbelieved = { believed: false, remainingMs: 0, halfSpent: true };
	it.each([
		["dated further ahead than the allowance", held, OBTAINED - 30_001],
		[
			"obtained after it expires",
			{ obtainedAt: at(OBTAINED + 1), expiresAt: at(OBTAINED) },
			OBTAINED + 10,
		],
		[
			"obtained as it expires",
			{ obtainedAt: at(OBTAINED), expiresAt: at(OBTAINED) },
			OBTAINED + 10,
		],
		[
			"an Invalid obtainedAt",
			{ obtainedAt: new Date(Number.NaN), expiresAt: at(OBTAINED + LIFETIME_MS) },
			OBTAINED + 10,
		],
		[
			"an Invalid expiresAt",
			{ obtainedAt: at(OBTAINED), expiresAt: new Date(Number.NaN) },
			OBTAINED + 10,
		],
		[
			"an obtainedAt that is not a Date",
			{ obtainedAt: OBTAINED as unknown as Date, expiresAt: at(OBTAINED + LIFETIME_MS) },
			OBTAINED + 10,
		],
	])("%s: not believed, and read as ended", (_, token, now) => {
		expect(judge(now, token)).toEqual(unbelieved);
	});

	it.each([
		["now NaN", { now: Number.NaN, allowanceMs: 0 }],
		["allowanceMs negative", { now: OBTAINED, allowanceMs: -1 }],
		["allowanceMs Infinity", { now: OBTAINED, allowanceMs: Number.POSITIVE_INFINITY }],
	])("%s throws a RangeError", (_, clock) => {
		expect(() => judgeHeldUpstreamToken(held, clock)).toThrow(RangeError);
	});
});
