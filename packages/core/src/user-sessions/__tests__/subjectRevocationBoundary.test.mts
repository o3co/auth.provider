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
import {
	checkSubjectRevocationInstant,
	clampSubjectRevocationBoundary,
} from "#/user-sessions/subjectRevocationBoundary.mjs";

const NOW = 1_800_000_000_000;

describe("checkSubjectRevocationInstant", () => {
	it("answers a Date's epoch milliseconds", () => {
		expect(checkSubjectRevocationInstant(new Date(NOW), "before")).toBe(NOW);
		expect(checkSubjectRevocationInstant(new Date(-1), "expiresAt")).toBe(-1);
	});

	it.each([
		["an Invalid Date", new Date(Number.NaN)],
		["a Date past the representable range", new Date(-1e20)],
		["an object whose getTime answers -Infinity", { getTime: () => Number.NEGATIVE_INFINITY }],
		["an object whose getTime answers +Infinity", { getTime: () => Number.POSITIVE_INFINITY }],
		["an object whose getTime answers a finite time", { getTime: () => NOW }],
		["a number", NOW],
		["a string", "2026-10-01T00:00:00Z"],
		["null", null],
		["undefined", undefined],
	])("refuses %s, naming the argument", (_label, value) => {
		// Only a Date with a finite time reads back as one: anything else
		// would compare as NaN or as a boundary no Date can hold.
		expect(() => checkSubjectRevocationInstant(value, "before")).toThrow(
			new RangeError("SubjectRevocation: before must be a date"),
		);
		expect(() => checkSubjectRevocationInstant(value, "expiresAt")).toThrow(
			new RangeError("SubjectRevocation: expiresAt must be a date"),
		);
	});
});

describe("clampSubjectRevocationBoundary", () => {
	it("keeps a boundary up to the store's clock plus DEFAULT_CLOCK_SKEW_MS as given", () => {
		for (const ms of [0, NOW, NOW + DEFAULT_CLOCK_SKEW_MS]) {
			const { boundary, clamped } = clampSubjectRevocationBoundary(new Date(ms), NOW);
			expect(boundary.getTime()).toBe(ms);
			expect(clamped).toBe(false);
		}
	});

	it("records one past it as the store's clock plus the skew, and says so", () => {
		const { boundary, clamped } = clampSubjectRevocationBoundary(
			new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1),
			NOW,
		);
		expect(boundary.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
		expect(clamped).toBe(true);
	});

	it("refuses a boundary that is not a date, before any clock is read", () => {
		expect(() => clampSubjectRevocationBoundary(new Date(Number.NaN), NOW)).toThrow(
			new RangeError("SubjectRevocation: before must be a date"),
		);
	});

	it.each([
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		["undefined", undefined],
		["-1e20, before the Date range", -1e20],
		["8.64e15, the Date range's end, whose bound lies past it", 8.64e15],
		["the Date range's start less the skew", -8.64e15 - DEFAULT_CLOCK_SKEW_MS - 1],
	])("refuses a store clock of %s: the bound is never skipped", (_label, storeNowMs) => {
		// A clock or a bound no Date can hold would record an Invalid Date,
		// a boundary every comparison reads as covering nothing.
		for (const before of [new Date(0), new Date(NOW)]) {
			expect(() => clampSubjectRevocationBoundary(before, storeNowMs as number)).toThrow(
				new RangeError("SubjectRevocation: the store's clock must be an instant a Date can hold"),
			);
		}
	});

	it("never answers an Invalid Date", () => {
		const latest = 8.64e15 - DEFAULT_CLOCK_SKEW_MS;
		const { boundary } = clampSubjectRevocationBoundary(new Date(8.64e15), latest);
		expect(boundary.getTime()).toBe(8.64e15);
	});
});

describe("createInMemorySubjectRevocation — its clock", () => {
	const recordingLogger = () => {
		const lines: Array<{ obj: Record<string, unknown>; msg: string | undefined }> = [];
		return {
			lines,
			logger: { warn: (obj: Record<string, unknown>, msg?: string) => lines.push({ obj, msg }) },
		};
	};

	it("records a boundary past its clock plus the skew as its clock plus the skew, for both methods", async () => {
		const store = createInMemorySubjectRevocation({ now: () => NOW });
		const ahead = new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 60_000);
		const until = new Date(NOW + 600_000);
		await store.revokeBefore("u", ahead, until);
		expect((await store.revokedBefore("u"))?.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
		await store.revokeSessionsBefore("v", ahead, until);
		expect((await store.revokedBefore("v"))?.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
		expect(await store.grantsRevokedBefore("v")).toBeNull();
	});

	it("bounds by the clock it is given, not the host's", async () => {
		const YEAR = 365 * 86_400_000;
		const host = Date.now();
		const until = new Date(host + 2 * YEAR);
		// Half a year past the host's clock: clamped on the host's, kept as given on a store a year ahead.
		const ahead = createInMemorySubjectRevocation({ now: () => host + YEAR });
		await ahead.revokeBefore("u", new Date(host + YEAR / 2), until);
		expect((await ahead.revokedBefore("u"))?.getTime()).toBe(host + YEAR / 2);
		// The host's own clock: kept as given on the host's, clamped on a store a year behind.
		const behind = createInMemorySubjectRevocation({ now: () => host - YEAR });
		await behind.revokeBefore("u", new Date(host), until);
		expect((await behind.revokedBefore("u"))?.getTime()).toBe(host - YEAR + DEFAULT_CLOCK_SKEW_MS);
	});

	it("says at warn that it clamped, once per clamped write, and nothing otherwise", async () => {
		const { lines, logger } = recordingLogger();
		const store = createInMemorySubjectRevocation({ now: () => NOW, logger });
		const until = new Date(NOW + 600_000);
		await store.revokeBefore("u", new Date(NOW), until);
		expect(lines).toEqual([]);
		await store.revokeSessionsBefore("u", new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 60_000), until);
		expect(lines).toEqual([
			{
				obj: {
					store: "memory",
					subject: "u",
					requestedBefore: new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 60_000).toISOString(),
					recordedBefore: new Date(NOW + DEFAULT_CLOCK_SKEW_MS).toISOString(),
				},
				msg: "subject_revocation_boundary_clamped",
			},
		]);
	});

	it("records the clamped boundary even when its logger throws", async () => {
		// The boundary is what ends tokens already issued: a failing log sink
		// must not cost the revocation.
		const logger = {
			warn: () => {
				throw new Error("log sink down");
			},
		};
		const store = createInMemorySubjectRevocation({ now: () => NOW, logger });
		const ahead = new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 60_000);
		await store.revokeBefore("u", ahead, new Date(NOW + 600_000));
		expect((await store.revokedBefore("u"))?.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
	});

	it("refuses an instant that is no Date, writing nothing", async () => {
		const store = createInMemorySubjectRevocation({ now: () => NOW });
		const until = new Date(NOW + 600_000);
		const fake = { getTime: () => Number.NEGATIVE_INFINITY } as unknown as Date;
		await expect(store.revokeBefore("u", fake, until)).rejects.toThrow(RangeError);
		await expect(store.revokeSessionsBefore("u", new Date(NOW), fake)).rejects.toThrow(RangeError);
		expect(await store.revokedBefore("u")).toBeNull();
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
