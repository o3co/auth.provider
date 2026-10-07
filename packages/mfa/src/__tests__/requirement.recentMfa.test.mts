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
 * `isRecentMfa`, the one reading of recent MFA (ADR
 * 2026-09-25-multi-factor-authentication, D16 and F4): a second factor
 * verified in the session within `mfa.manage.maxAgeSeconds`, in a session
 * whose vouched `amr` holds `mfa`, a time up to `DEFAULT_CLOCK_SKEW_MS` ahead
 * read as now and one further ahead as not recent; for a subject with no
 * counting factor, a primary that recent instead.
 */

import { DEFAULT_CLOCK_SKEW_MS } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { isRecentMfa } from "#/requirement.mjs";

const NOW = Date.parse("2026-09-30T12:00:00Z");
const WINDOW_SECONDS = 300;
const secondsAgo = (seconds: number): Date => new Date(NOW - seconds * 1_000);
const msAhead = (ms: number): Date => new Date(NOW + ms);

/** Recent MFA for a subject that holds a counting factor, over a primary as old as the window allows twice over. */
const withFactor = (mfaAt: Date | undefined, authTime: Date = secondsAgo(2 * WINDOW_SECONDS)) =>
	isRecentMfa(
		{ authTime, mfaAt, holdsMfa: true },
		{ holdsCountingFactor: true },
		WINDOW_SECONDS,
		NOW,
	);

/** Recent MFA for a subject that holds no counting factor. */
const withoutFactor = (authTime: Date, mfaAt?: Date) =>
	isRecentMfa(
		{ authTime, mfaAt, holdsMfa: true },
		{ holdsCountingFactor: false },
		WINDOW_SECONDS,
		NOW,
	);

describe("isRecentMfa — a second factor verified in the session", () => {
	it("is recent inside the window", () => {
		expect(withFactor(secondsAgo(60))).toBe(true);
		expect(withFactor(new Date(NOW))).toBe(true);
	});

	it("is not recent outside the window", () => {
		expect(withFactor(secondsAgo(WINDOW_SECONDS + 1))).toBe(false);
		expect(withFactor(secondsAgo(24 * 60 * 60))).toBe(false);
	});

	it("is recent at the window's edge, and not a millisecond past it", () => {
		expect(withFactor(secondsAgo(WINDOW_SECONDS))).toBe(true);
		expect(withFactor(new Date(NOW - WINDOW_SECONDS * 1_000 - 1))).toBe(false);
	});

	it("reads an mfaAt up to the tolerated clock skew ahead as now", () => {
		expect(withFactor(msAhead(1))).toBe(true);
		expect(withFactor(msAhead(DEFAULT_CLOCK_SKEW_MS))).toBe(true);
	});

	it("reads an mfaAt further ahead than the tolerated clock skew as not recent", () => {
		expect(withFactor(msAhead(DEFAULT_CLOCK_SKEW_MS + 1))).toBe(false);
		expect(withFactor(msAhead(24 * 60 * 60 * 1_000))).toBe(false);
	});

	it("is not recent without an mfaAt: for a subject who holds a counting factor, a recent primary does not stand in", () => {
		expect(withFactor(undefined, new Date(NOW))).toBe(false);
		expect(withFactor(undefined, secondsAgo(1))).toBe(false);
	});

	it("is not recent for an mfaAt that is not a valid date", () => {
		expect(withFactor(new Date(Number.NaN), new Date(NOW))).toBe(false);
	});

	it("measures the window given: a longer one keeps an older mfaAt recent, a shorter one does not", () => {
		const at = secondsAgo(1_800);
		const within = (maxAgeSeconds: number) =>
			isRecentMfa(
				{ authTime: secondsAgo(7_200), mfaAt: at, holdsMfa: true },
				{ holdsCountingFactor: true },
				maxAgeSeconds,
				NOW,
			);
		expect(within(3_600)).toBe(true);
		expect(within(60)).toBe(false);
	});

	it("is not recent when the clock it is asked at is not a finite time", () => {
		for (const nowMs of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			const recent = { authTime: new Date(NOW), mfaAt: new Date(NOW), holdsMfa: true };
			expect(isRecentMfa(recent, { holdsCountingFactor: true }, WINDOW_SECONDS, nowMs)).toBe(false);
			expect(isRecentMfa(recent, { holdsCountingFactor: false }, WINDOW_SECONDS, nowMs)).toBe(
				false,
			);
		}
	});

	it("is not recent under a window that is not a finite number of seconds", () => {
		for (const maxAgeSeconds of [Number.NaN, Number.POSITIVE_INFINITY]) {
			const recent = { authTime: secondsAgo(1), mfaAt: secondsAgo(1), holdsMfa: true };
			expect(isRecentMfa(recent, { holdsCountingFactor: true }, maxAgeSeconds, NOW)).toBe(false);
			expect(isRecentMfa(recent, { holdsCountingFactor: false }, maxAgeSeconds, NOW)).toBe(false);
		}
	});
});

describe("isRecentMfa — a second factor counts only in a session that holds mfa", () => {
	/** Recent MFA for a subject that holds a counting factor, over a session that holds `mfa` or not. */
	const vouched = (holdsMfa: boolean, mfaAt: Date | undefined = secondsAgo(60)) =>
		isRecentMfa(
			{ authTime: secondsAgo(2 * WINDOW_SECONDS), mfaAt, holdsMfa },
			{ holdsCountingFactor: true },
			WINDOW_SECONDS,
			NOW,
		);

	it("is not recent after a second factor inside the window in a session without mfa: an email code's", () => {
		expect(vouched(false)).toBe(false);
		expect(vouched(false, new Date(NOW))).toBe(false);
	});

	it("is recent after the same second factor in a session that holds mfa", () => {
		expect(vouched(true)).toBe(true);
	});

	it("still stands a recent primary in for a subject who holds no counting factor, in a session without mfa", () => {
		expect(
			isRecentMfa(
				{ authTime: secondsAgo(60), mfaAt: undefined, holdsMfa: false },
				{ holdsCountingFactor: false },
				WINDOW_SECONDS,
				NOW,
			),
		).toBe(true);
	});
});

describe("isRecentMfa — a subject with no counting factor: a recent primary instead", () => {
	it("is recent when the primary is inside the window, with no mfaAt", () => {
		expect(withoutFactor(secondsAgo(60))).toBe(true);
	});

	it("is not recent when the primary is outside the window", () => {
		expect(withoutFactor(secondsAgo(WINDOW_SECONDS + 1))).toBe(false);
	});

	it("is recent at the window's edge, and not a millisecond past it", () => {
		expect(withoutFactor(secondsAgo(WINDOW_SECONDS))).toBe(true);
		expect(withoutFactor(new Date(NOW - WINDOW_SECONDS * 1_000 - 1))).toBe(false);
	});

	it("reads a primary up to the tolerated clock skew ahead as now, and one further ahead as not recent", () => {
		expect(withoutFactor(msAhead(DEFAULT_CLOCK_SKEW_MS))).toBe(true);
		expect(withoutFactor(msAhead(DEFAULT_CLOCK_SKEW_MS + 1))).toBe(false);
	});

	it("is not recent for a primary time that is not a valid date", () => {
		expect(withoutFactor(new Date(Number.NaN))).toBe(false);
	});

	it("is recent over a stale primary when a second factor was verified inside the window", () => {
		expect(withoutFactor(secondsAgo(24 * 60 * 60), secondsAgo(60))).toBe(true);
	});

	it("is not recent over a stale primary and a stale second factor", () => {
		expect(withoutFactor(secondsAgo(24 * 60 * 60), secondsAgo(WINDOW_SECONDS + 1))).toBe(false);
	});
});
