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

import { runInNewContext } from "node:vm";
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

/** Dates no reading may trust or be thrown out of: each must read as no Date at all. */
const hostileDates = (ms: number): ReadonlyArray<readonly [string, unknown]> => {
	const revocable = Proxy.revocable(new Date(ms), {});
	revocable.revoke();
	return [
		["a Proxy around a Date", new Proxy(new Date(ms), {})],
		["a revoked Proxy", revocable.proxy],
		["a Date from another realm", runInNewContext("new Date(ms)", { ms })],
		["an object that only inherits from Date", Object.create(Date.prototype)],
	];
};

/** A value that answers `first` on its first read and `then` on every later one. */
const flipping = (first: number, then: number): (() => number) => {
	let reads = 0;
	return () => (reads++ === 0 ? first : then);
};

/** Clock values that are not numbers: none may be coerced into one, and none may throw anything but a RangeError. */
const NOT_NUMBERS: ReadonlyArray<readonly [string, unknown]> = [
	["a numeric string", "0"],
	["null", null],
	["undefined", undefined],
	["a bigint", 1n],
	["a symbol", Symbol()],
	["a boxed number", Object(0)],
];

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
		// Beyond the Date range: the derived instant.
		["expiresIn whose instant leaves the Date range", MAX_INSTANT_MS / 1000, undefined],
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

	it.each(hostileDates(CALLED_AT + 3_600_000))(
		"expiresAt %s: malformed, never thrown",
		(_, date) => {
			expect(read(undefined, date)).toEqual({ verdict: "malformed" });
			expect(read(3600, date)).toEqual({ verdict: "malformed" });
		},
	);

	it("the derived instant at the end of the Date range is finite, and a millisecond beyond it malformed", () => {
		const clockAt = (calledAt: number) => ({ calledAt, now: calledAt, floorMs: 1000 });
		const fields = { expiresIn: 3600, expiresAt: undefined };
		const last = finite(readUpstreamTokenLifetime(fields, clockAt(MAX_INSTANT_MS - 3_600_000)));
		expect(last.expiresAt.getTime()).toBe(MAX_INSTANT_MS);
		expect(readUpstreamTokenLifetime(fields, clockAt(MAX_INSTANT_MS - 3_599_999))).toEqual({
			verdict: "malformed",
		});
	});

	it("an expiresIn whose start would lie before the Date range, beside a usable expiresAt, is finite: nothing is dated back", () => {
		const reading = finite(read(1e13, at(CALLED_AT + 3_600_000)));
		expect(reading.obtainedAt.getTime()).toBe(CALLED_AT);
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 3_600_000);
		expect(reading).toHaveProperty("issuedLifetime", 1e13);
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

	it("both fields, expiresAt earlier than calledAt + expiresIn: the earlier ends it, it is dated from the call, and the lifetime is kept as issued", () => {
		// Dated back to fit the issued lifetime, it would be half spent the moment
		// it was obtained; shortened to fit the end, a maximum would judge less
		// than was issued.
		const reading = finite(read(3600, at(CALLED_AT + 1_800_000)));
		expect(reading).toEqual({
			verdict: "finite",
			stated: "both",
			obtainedAt: at(CALLED_AT),
			expiresAt: at(CALLED_AT + 1_800_000),
			issuedLifetime: 3600,
		});
	});

	it("both fields, expiresAt far later than calledAt + expiresIn: it cannot lengthen the lifetime", () => {
		const reading = finite(read(3600, at(MAX_INSTANT_MS)));
		expect(reading.stated).toBe("both");
		expect(reading.obtainedAt.getTime()).toBe(CALLED_AT);
		expect(reading.expiresAt.getTime()).toBe(CALLED_AT + 3_600_000);
		expect(reading).toHaveProperty("issuedLifetime", 3600);
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
		expect(reading).toHaveProperty("issuedLifetime", 1.5);
	});

	it("expiresAt alone: dated from the call, and no lifetime was issued", () => {
		expect(finite(read(undefined, at(CALLED_AT + 1_800_000)))).toEqual({
			verdict: "finite",
			stated: "expiresAt",
			obtainedAt: at(CALLED_AT),
			expiresAt: at(CALLED_AT + 1_800_000),
		});
	});

	it("expiresAt alone at the end of the Date range is finite: a maximum is the consumer's", () => {
		const reading = finite(read(undefined, at(MAX_INSTANT_MS)));
		expect(reading.expiresAt.getTime()).toBe(MAX_INSTANT_MS);
		expect(reading).not.toHaveProperty("issuedLifetime");
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
		["both, the instant far later", 3600, at(MAX_INSTANT_MS)],
		["expiresIn alone, a fractional millisecond", 1.0005, undefined],
	])(
		"%s: obtainedAt is calledAt, expiresAt is after it and no later than a stated expiresIn allows, which is kept as issued",
		(_, expiresIn, expiresAt) => {
			const reading = finite(read(expiresIn, expiresAt, 0));
			expect(reading.obtainedAt.getTime()).toBe(CALLED_AT);
			const span = reading.expiresAt.getTime() - reading.obtainedAt.getTime();
			expect(span).toBeGreaterThan(0);
			if (typeof expiresIn === "number") {
				expect(reading).toHaveProperty("issuedLifetime", expiresIn);
				expect(span).toBeLessThanOrEqual(expiresIn * 1000);
			} else {
				expect(reading).not.toHaveProperty("issuedLifetime");
			}
		},
	);
});

describe("readUpstreamTokenLifetime — the clock is the consumer's to get right", () => {
	it.each([
		["calledAt NaN", { calledAt: Number.NaN, now: NOW, floorMs: 1000 }],
		["calledAt Infinity", { calledAt: Number.POSITIVE_INFINITY, now: NOW, floorMs: 1000 }],
		["calledAt beyond the Date range", { calledAt: MAX_INSTANT_MS + 1, now: NOW, floorMs: 1000 }],
		["now NaN", { calledAt: CALLED_AT, now: Number.NaN, floorMs: 1000 }],
		["now Infinity", { calledAt: CALLED_AT, now: Number.POSITIVE_INFINITY, floorMs: 1000 }],
		["now before the Date range", { calledAt: CALLED_AT, now: -MAX_INSTANT_MS - 1, floorMs: 1000 }],
		["floorMs negative", { calledAt: CALLED_AT, now: NOW, floorMs: -1 }],
		["floorMs NaN", { calledAt: CALLED_AT, now: NOW, floorMs: Number.NaN }],
		["floorMs Infinity", { calledAt: CALLED_AT, now: NOW, floorMs: Number.POSITIVE_INFINITY }],
	])("%s throws a RangeError", (_, clock) => {
		expect(() =>
			readUpstreamTokenLifetime({ expiresIn: 3600, expiresAt: undefined }, clock),
		).toThrow(RangeError);
	});

	it.each(
		(["calledAt", "now", "floorMs"] as const).flatMap((field) =>
			NOT_NUMBERS.map(([label, value]) => [field, label, value] as const),
		),
	)("%s as %s throws a RangeError", (field, _, value) => {
		const clock = { calledAt: CALLED_AT, now: NOW, floorMs: 1000, [field]: value };
		expect(() =>
			readUpstreamTokenLifetime(
				{ expiresIn: 3600, expiresAt: undefined },
				clock as unknown as { calledAt: number; now: number; floorMs: number },
			),
		).toThrow(RangeError);
	});

	it("reads each clock field once: a floor that answers differently later cannot be skipped", () => {
		const floorMs = flipping(1000, Number.NaN);
		const clock = {
			calledAt: CALLED_AT,
			now: NOW,
			get floorMs() {
				return floorMs();
			},
		};
		expect(
			readUpstreamTokenLifetime({ expiresIn: undefined, expiresAt: at(NOW + 500) }, clock),
		).toEqual({
			verdict: "spent",
		});
	});

	it("reads each clock field once: a now that answers differently later cannot lengthen what is left", () => {
		const now = flipping(NOW, NOW - 10_000);
		const clock = {
			calledAt: CALLED_AT,
			get now() {
				return now();
			},
			floorMs: 1000,
		};
		expect(
			readUpstreamTokenLifetime({ expiresIn: undefined, expiresAt: at(NOW + 500) }, clock),
		).toEqual({
			verdict: "spent",
		});
	});

	it("reads each clock field once: a calledAt that answers differently later cannot move the dating", () => {
		const calledAt = flipping(CALLED_AT, CALLED_AT + 1_000_000);
		const clock = {
			get calledAt() {
				return calledAt();
			},
			now: NOW,
			floorMs: 1000,
		};
		expect(readUpstreamTokenLifetime({ expiresIn: 1, expiresAt: undefined }, clock)).toEqual({
			verdict: "spent",
		});
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

	it.each(hostileDates(OBTAINED))("obtainedAt %s: not believed, never thrown", (_, date) => {
		expect(judge(OBTAINED + 10, { obtainedAt: date as Date, expiresAt: held.expiresAt })).toEqual(
			unbelieved,
		);
	});

	it.each(hostileDates(OBTAINED + LIFETIME_MS))(
		"expiresAt %s: not believed, never thrown",
		(_, date) => {
			expect(
				judge(OBTAINED + 10, { obtainedAt: held.obtainedAt, expiresAt: date as Date }),
			).toEqual(unbelieved);
		},
	);

	it("a held Date whose getTime is overridden is read by its own value", () => {
		const obtainedAt = at(OBTAINED);
		obtainedAt.getTime = () => OBTAINED + LIFETIME_MS;
		expect(judge(OBTAINED + 10, { obtainedAt, expiresAt: held.expiresAt })).toEqual({
			believed: true,
			remainingMs: LIFETIME_MS - 10,
			halfSpent: false,
		});
	});

	it("every result not believed is its own: changing one does not make the next believed", () => {
		const first = judge(OBTAINED - 30_001);
		const second = judge(OBTAINED - 30_001);
		expect(second).not.toBe(first);
		(first as { believed: boolean }).believed = true;
		expect(judge(OBTAINED - 30_001).believed).toBe(false);
	});

	it("reads each clock field once: an allowance that answers differently later cannot believe a token", () => {
		const allowanceMs = flipping(0, Number.POSITIVE_INFINITY);
		const clock = {
			now: OBTAINED - 1,
			get allowanceMs() {
				return allowanceMs();
			},
		};
		expect(judgeHeldUpstreamToken(held, clock)).toEqual(unbelieved);
	});

	it("reads each clock field once: a now that answers differently later cannot believe a token", () => {
		const now = flipping(OBTAINED - 1_000_000, OBTAINED);
		const clock = {
			get now() {
				return now();
			},
			allowanceMs: 30_000,
		};
		expect(judgeHeldUpstreamToken(held, clock)).toEqual(unbelieved);
	});

	it.each([
		["now NaN", { now: Number.NaN, allowanceMs: 0 }],
		["now beyond the Date range", { now: MAX_INSTANT_MS + 1, allowanceMs: 0 }],
		["allowanceMs NaN", { now: OBTAINED, allowanceMs: Number.NaN }],
		["allowanceMs negative", { now: OBTAINED, allowanceMs: -1 }],
		["allowanceMs Infinity", { now: OBTAINED, allowanceMs: Number.POSITIVE_INFINITY }],
	])("%s throws a RangeError", (_, clock) => {
		expect(() => judgeHeldUpstreamToken(held, clock)).toThrow(RangeError);
	});

	it.each(
		(["now", "allowanceMs"] as const).flatMap((field) =>
			NOT_NUMBERS.map(([label, value]) => [field, label, value] as const),
		),
	)("%s as %s throws a RangeError", (field, _, value) => {
		const clock = { now: OBTAINED, allowanceMs: 0, [field]: value };
		expect(() =>
			judgeHeldUpstreamToken(held, clock as unknown as { now: number; allowanceMs: number }),
		).toThrow(RangeError);
	});
});
