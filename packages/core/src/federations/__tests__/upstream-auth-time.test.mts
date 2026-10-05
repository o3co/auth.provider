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
import { readUpstreamAuthTime } from "#/federations/upstream-auth-time.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";

const NOW_MS = Date.parse("2026-10-05T12:00:00Z");
const NOW_S = NOW_MS / 1000;

describe("readUpstreamAuthTime — an upstream id_token's auth_time", () => {
	it("answers undefined when the id_token carried none", () => {
		expect(readUpstreamAuthTime(undefined, NOW_MS)).toBeUndefined();
	});

	it("answers the instant of whole epoch seconds, the epoch itself included", () => {
		expect(readUpstreamAuthTime(NOW_S - 60, NOW_MS)).toEqual(new Date(NOW_MS - 60_000));
		expect(readUpstreamAuthTime(0, NOW_MS)).toEqual(new Date(0));
	});

	it("floors a fractional value to its whole second: never an instant later than the claim", () => {
		expect(readUpstreamAuthTime(NOW_S - 0.5, NOW_MS)).toEqual(new Date(NOW_MS - 1_000));
		expect(readUpstreamAuthTime(NOW_S - 59.999, NOW_MS)).toEqual(new Date(NOW_MS - 60_000));
		expect(readUpstreamAuthTime(0.5, NOW_MS)).toEqual(new Date(0));
	});

	it("answers an instant up to the clock skew tolerated between hosts ahead of the clock", () => {
		const aheadS = NOW_S + DEFAULT_CLOCK_SKEW_MS / 1000;
		expect(readUpstreamAuthTime(aheadS, NOW_MS)).toEqual(new Date(aheadS * 1000));
	});

	it("answers invalid for an instant further ahead: it would read as fresher than any ask", () => {
		expect(readUpstreamAuthTime(NOW_S + DEFAULT_CLOCK_SKEW_MS / 1000 + 1, NOW_MS)).toBe("invalid");
	});

	it.each([
		["null", null],
		["a string", String(NOW_S)],
		["a boolean", true],
		["a negative number", -1],
		["a negative fraction", -0.5],
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		["an unsafe integer", Number.MAX_SAFE_INTEGER + 1],
		["one past the Date range", 8_640_000_000_001],
		["a bigint", BigInt(NOW_S)],
		["an object", { seconds: NOW_S }],
		["an object with valueOf", { valueOf: () => NOW_S }],
	])("answers invalid for a claim that is %s", (_label, claim) => {
		expect(readUpstreamAuthTime(claim, NOW_MS)).toBe("invalid");
	});

	it("answers a fresh Date each time", () => {
		const first = readUpstreamAuthTime(NOW_S, NOW_MS);
		const second = readUpstreamAuthTime(NOW_S, NOW_MS);
		expect(first).toEqual(second);
		expect(first).not.toBe(second);
	});

	it("reads against the current clock when given none", () => {
		expect(readUpstreamAuthTime(Math.floor(Date.now() / 1000) - 1)).toBeInstanceOf(Date);
		expect(readUpstreamAuthTime(Math.floor(Date.now() / 1000) + 3600)).toBe("invalid");
	});

	it.each([
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
	])("throws a RangeError for a clock that is %s", (_label, nowMs) => {
		expect(() => readUpstreamAuthTime(NOW_S, nowMs)).toThrow(RangeError);
	});
});
