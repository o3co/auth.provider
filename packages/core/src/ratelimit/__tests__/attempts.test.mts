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
 * The `AttemptCounter` port's vocabulary: which specs and keys a counter
 * takes, and the one reading of its answer.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import {
	ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS,
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	isAttemptKey,
	isAttemptSpec,
	MAX_ATTEMPT_KEY_LENGTH,
	MAX_ATTEMPT_WINDOW_SECONDS,
	readAttemptCount,
} from "#/ratelimit/attempts.mjs";
import type { RateLimiter } from "#/ratelimit/types.mjs";

const SPEC: AttemptSpec = { limit: 5, windowSeconds: 60 };
const RESET = new Date("2026-10-03T00:01:00.000Z");
/** Half a window before RESET: the reading's clock. */
const NOW = RESET.getTime() - 30_000;

describe("AttemptCounter", () => {
	it("consumes against a spec handed in by the caller, and is not a RateLimiter", () => {
		expectTypeOf<AttemptCounter["consume"]>().parameters.toEqualTypeOf<[string, AttemptSpec]>();
		expectTypeOf<AttemptCounter["consume"]>().returns.toEqualTypeOf<Promise<AttemptCount>>();
		expectTypeOf<AttemptCounter>().not.toExtend<RateLimiter>();
		expectTypeOf<RateLimiter>().not.toExtend<AttemptCounter>();
	});
});

describe("isAttemptSpec", () => {
	it("accepts a positive whole limit and a positive whole window of at most a day", () => {
		expect(MAX_ATTEMPT_WINDOW_SECONDS).toBe(86_400);
		expect(isAttemptSpec({ limit: 1, windowSeconds: 1 })).toBe(true);
		expect(isAttemptSpec({ limit: 20, windowSeconds: 86_400 })).toBe(true);
	});

	it.each([
		["null", null],
		["a number", 5],
		["no limit", { windowSeconds: 60 }],
		["no window", { limit: 5 }],
		["a zero limit", { limit: 0, windowSeconds: 60 }],
		["a negative limit", { limit: -1, windowSeconds: 60 }],
		["a fractional limit", { limit: 1.5, windowSeconds: 60 }],
		["a NaN limit", { limit: Number.NaN, windowSeconds: 60 }],
		["an unsafe limit", { limit: 2 ** 53, windowSeconds: 60 }],
		["a string limit", { limit: "5", windowSeconds: 60 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a window past a day", { limit: 5, windowSeconds: 86_401 }],
		["an infinite window", { limit: 5, windowSeconds: Number.POSITIVE_INFINITY }],
	])("refuses %s", (_label, value) => {
		expect(isAttemptSpec(value)).toBe(false);
	});
});

describe("isAttemptKey", () => {
	it("accepts a non-empty string of at most 512 characters", () => {
		expect(MAX_ATTEMPT_KEY_LENGTH).toBe(512);
		expect(isAttemptKey("login:ip:192.0.2.1")).toBe(true);
		expect(isAttemptKey("k".repeat(512))).toBe(true);
	});

	it.each([
		["an empty string", ""],
		["a string of 513 characters", "k".repeat(513)],
		["a number", 1],
		["undefined", undefined],
		["an object", { toString: () => "k" }],
	])("refuses %s", (_label, value) => {
		expect(isAttemptKey(value)).toBe(false);
	});
});

describe("readAttemptCount", () => {
	it("reads an allowed count into a fresh, frozen copy", () => {
		const answer = { allowed: true, remaining: 4, resetAt: new Date(RESET) };
		const read = readAttemptCount(answer, SPEC, NOW);
		expect(read).toEqual({ allowed: true, remaining: 4, resetAt: RESET });
		expect(Object.isFrozen(read)).toBe(true);
		answer.resetAt.setTime(0);
		expect(read?.resetAt.getTime()).toBe(RESET.getTime());
	});

	it("reads a refusal with nothing remaining", () => {
		expect(readAttemptCount({ allowed: false, remaining: 0, resetAt: RESET }, SPEC, NOW)).toEqual({
			allowed: false,
			remaining: 0,
			resetAt: RESET,
		});
	});

	it("reads each field once", () => {
		const reads: string[] = [];
		const answer = {
			get allowed() {
				reads.push("allowed");
				return true;
			},
			get remaining() {
				reads.push("remaining");
				return 1;
			},
			get resetAt() {
				reads.push("resetAt");
				return RESET;
			},
		};
		expect(readAttemptCount(answer, SPEC, NOW)?.remaining).toBe(1);
		expect(reads.sort()).toEqual(["allowed", "remaining", "resetAt"]);
	});

	it.each([
		["null", null],
		["a string", "allowed"],
		["allowed not a boolean", { allowed: "yes", remaining: 1, resetAt: RESET }],
		["remaining missing", { allowed: true, resetAt: RESET }],
		["remaining fractional", { allowed: true, remaining: 1.5, resetAt: RESET }],
		["remaining negative", { allowed: true, remaining: -1, resetAt: RESET }],
		["remaining NaN", { allowed: true, remaining: Number.NaN, resetAt: RESET }],
		[
			"remaining as many as the limit on an allowed attempt",
			{ allowed: true, remaining: 5, resetAt: RESET },
		],
		["remaining left on a refusal", { allowed: false, remaining: 1, resetAt: RESET }],
		["resetAt missing", { allowed: true, remaining: 1 }],
		["resetAt a number", { allowed: true, remaining: 1, resetAt: RESET.getTime() }],
		["resetAt an Invalid Date", { allowed: true, remaining: 1, resetAt: new Date(Number.NaN) }],
	])("answers undefined for %s", (_label, answer) => {
		expect(readAttemptCount(answer, SPEC, NOW)).toBeUndefined();
	});

	it("reads a window's end from the allowance before now to a day and the allowance after it, whatever the spec's window", () => {
		expect(ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS).toBe(5_000);
		const at = (ms: number) =>
			readAttemptCount({ allowed: true, remaining: 1, resetAt: new Date(ms) }, SPEC, NOW);
		expect(at(NOW - 5_000)?.resetAt.getTime()).toBe(NOW - 5_000);
		expect(at(NOW + 86_400_000 + 5_000)?.resetAt.getTime()).toBe(NOW + 86_405_000);
		expect(at(NOW - 5_001)).toBeUndefined();
		expect(at(NOW + 86_405_001)).toBeUndefined();
		expect(at(NOW + 365 * 86_400_000)).toBeUndefined();
		// A window started under an earlier, longer spec, up to the one-day cap, is still a count.
		expect(at(NOW + 900_000)?.resetAt.getTime()).toBe(NOW + 900_000);
		expect(at(NOW + 86_400_000)?.resetAt.getTime()).toBe(NOW + 86_400_000);
		expect(
			readAttemptCount({ allowed: true, remaining: 1, resetAt: RESET }, SPEC, Number.NaN),
		).toBeUndefined();
	});

	it("answers undefined, never throws, for an answer whose read throws", () => {
		const answer = {
			allowed: true,
			remaining: 1,
			get resetAt(): Date {
				throw new Error("getter");
			},
		};
		expect(readAttemptCount(answer, SPEC, NOW)).toBeUndefined();
	});
});
