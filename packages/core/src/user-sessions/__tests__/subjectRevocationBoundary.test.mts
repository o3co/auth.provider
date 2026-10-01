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
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { checkSubjectRevocationBoundary } from "#/user-sessions/subjectRevocationBoundary.mjs";

const NOW = 1_800_000_000_000;

describe("checkSubjectRevocationBoundary", () => {
	it("answers the boundary's epoch milliseconds", () => {
		expect(checkSubjectRevocationBoundary(new Date(NOW))).toBe(NOW);
		expect(checkSubjectRevocationBoundary(new Date(NOW), NOW)).toBe(NOW);
	});

	it.each([
		["an Invalid Date", new Date(Number.NaN)],
		["a number", NOW],
		["a string", "2026-10-01T00:00:00Z"],
		["null", null],
		["undefined", undefined],
	])("refuses %s as no date", (_label, value) => {
		expect(() => checkSubjectRevocationBoundary(value)).toThrow(
			new RangeError("SubjectRevocation: before must be a date"),
		);
	});

	it("accepts a boundary up to the store's clock plus DEFAULT_CLOCK_SKEW_MS", () => {
		const edge = NOW + DEFAULT_CLOCK_SKEW_MS;
		expect(checkSubjectRevocationBoundary(new Date(edge), NOW)).toBe(edge);
	});

	it("refuses one past it, naming the bound", () => {
		expect(() =>
			checkSubjectRevocationBoundary(new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1), NOW),
		).toThrow(
			new RangeError(
				"SubjectRevocation: before must be no further ahead of the store's clock than DEFAULT_CLOCK_SKEW_MS",
			),
		);
	});

	it("does not refuse one behind the store's clock, however far", () => {
		expect(checkSubjectRevocationBoundary(new Date(0), NOW)).toBe(0);
	});

	it("refuses every boundary against a clock that is not a number", () => {
		expect(() => checkSubjectRevocationBoundary(new Date(0), Number.NaN)).toThrow(RangeError);
	});
});

describe("createInMemorySubjectRevocation — its clock", () => {
	it("judges the boundary on the clock it is given, not the host's", async () => {
		const store = createInMemorySubjectRevocation({ now: () => NOW });
		const ahead = new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1);
		const until = new Date(NOW + 600_000);
		await expect(store.revokeBefore("u", ahead, until)).rejects.toThrow(RangeError);
		await expect(store.revokeSessionsBefore("u", ahead, until)).rejects.toThrow(RangeError);
		expect(await store.revokedBefore("u")).toBeNull();
		// The host's clock is years behind NOW, so this is "ahead" only for the host.
		await store.revokeBefore("u", new Date(NOW), until);
		expect((await store.revokedBefore("u"))?.getTime()).toBe(NOW);
	});

	it("lets a record lapse on that clock", async () => {
		let now = NOW;
		const store = createInMemorySubjectRevocation({ now: () => now });
		await store.revokeSessionsBefore("u", new Date(NOW), new Date(NOW + 1_000));
		expect((await store.revokedBefore("u"))?.getTime()).toBe(NOW);
		now = NOW + 1_000;
		expect(await store.revokedBefore("u")).toBeNull();
	});
});
