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
 * The rule every keystore applies to a previous key's retirement: a date is
 * read once, as epoch milliseconds, and refused unless it is a Date holding a
 * valid time; a key verifies only strictly before that time, and a time that
 * cannot be compared counts as passed.
 */

import { describe, expect, it } from "vitest";
import { readRetirementTimes, verifiesBefore } from "#/keys/retirement.mjs";

describe("the retirement rule", () => {
	it("reads a valid Date as its epoch milliseconds", () => {
		expect(readRetirementTimes("owner", [["previousKeys[0].expiresAt", new Date(5_000)]])).toEqual([
			5_000,
		]);
	});

	it("names where the unusable date was configured, and the owner", () => {
		expect(() =>
			readRetirementTimes("createX", [
				["previousKeys[0].expiresAt", new Date(1)],
				["previousKeys[1].expiresAt", new Date(Number.NaN)],
			]),
		).toThrow(/^createX: previousKeys\[1\]\.expiresAt /);
	});

	it("lets a key verify only strictly before its retirement time", () => {
		expect(verifiesBefore(1_000, 999)).toBe(true);
		expect(verifiesBefore(1_000, 1_000)).toBe(false);
		expect(verifiesBefore(1_000, 1_001)).toBe(false);
	});

	it("counts a retirement time it cannot compare as passed", () => {
		expect(verifiesBefore(Number.NaN, 0)).toBe(false);
		expect(verifiesBefore(1_000, Number.NaN)).toBe(false);
	});
});
