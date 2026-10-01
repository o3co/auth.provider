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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refreshIsDue } from "#/routes/federationTokenRefreshDue.mjs";

const NOW = Date.UTC(2026, 9, 2, 12, 0, 0);
const BUFFER_MS = 30_000;
const at = (ms: number) => ({ expiresAt: new Date(ms) });

describe("refreshIsDue", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"], now: NOW });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("never refreshes a token with no finite expiry", () => {
		expect(refreshIsDue({ refreshBufferMs: BUFFER_MS }, { expiresAt: null })).toBe(false);
	});

	it("refreshes a token whose remaining life equals the buffer", () => {
		expect(refreshIsDue({ refreshBufferMs: BUFFER_MS }, at(NOW + BUFFER_MS))).toBe(true);
	});

	it("does not refresh a token with a millisecond more than the buffer left", () => {
		expect(refreshIsDue({ refreshBufferMs: BUFFER_MS }, at(NOW + BUFFER_MS + 1))).toBe(false);
	});

	it("refreshes a stored expiry that names no instant", () => {
		expect(refreshIsDue({ refreshBufferMs: BUFFER_MS }, at(Number.NaN))).toBe(true);
	});

	it("honours the buffer it is given", () => {
		expect(refreshIsDue({ refreshBufferMs: 120_000 }, at(NOW + 60_000))).toBe(true);
		expect(refreshIsDue({ refreshBufferMs: 1000 }, at(NOW + 60_000))).toBe(false);
	});

	describe("a token known to be obtained at a time: never refreshed before it is half spent", () => {
		const LIFE_MS = 10_000;
		const held = (obtainedAt: number, lifeMs = LIFE_MS) => ({
			obtainedAt: new Date(obtainedAt),
			expiresAt: new Date(obtainedAt + lifeMs),
		});
		const due = (tokens: { obtainedAt?: Date; expiresAt: Date | null }) =>
			refreshIsDue({ refreshBufferMs: BUFFER_MS }, tokens);

		it("does not refresh a lifetime shorter than the buffer before its midpoint", () => {
			expect(due(held(NOW))).toBe(false);
			expect(due(held(NOW - LIFE_MS / 2 + 1))).toBe(false);
		});

		it("refreshes it from its midpoint", () => {
			expect(due(held(NOW - LIFE_MS / 2))).toBe(true);
			expect(due(held(NOW - LIFE_MS + 1))).toBe(true);
		});

		it("refreshes it once it has ended", () => {
			expect(due(held(NOW - LIFE_MS))).toBe(true);
			expect(due(held(NOW - 2 * LIFE_MS))).toBe(true);
		});

		it("only ever delays a refresh: a half-spent token outside the buffer is not due", () => {
			expect(due(held(NOW - 3_600_000, 2 * 3_600_000))).toBe(false);
		});

		it("never refreshes a token with no finite expiry, whatever its obtainedAt", () => {
			expect(due({ obtainedAt: new Date(NOW - 3_600_000), expiresAt: null })).toBe(false);
		});

		it("keeps the buffer rule for a record without obtainedAt", () => {
			expect(due({ expiresAt: new Date(NOW + LIFE_MS) })).toBe(true);
		});

		it("keeps the buffer rule for an obtainedAt that names no instant, as for an absent one", () => {
			expect(due({ obtainedAt: new Date(Number.NaN), expiresAt: new Date(NOW + LIFE_MS) })).toBe(
				true,
			);
		});

		it("refreshes a token with less than a second left, half spent or not", () => {
			// Never handed on with no whole second left: the floor a refresh answer is held to.
			expect(due({ obtainedAt: new Date(NOW - 100), expiresAt: new Date(NOW + 999) })).toBe(true);
			expect(due({ obtainedAt: new Date(NOW - 100), expiresAt: new Date(NOW + 1000) })).toBe(false);
		});

		it("believes an obtainedAt a little ahead of now, as another replica's clock may be", () => {
			expect(due(held(NOW + 5000))).toBe(false);
		});

		it("keeps the buffer rule for an obtainedAt it does not believe: one not before its own end", () => {
			// Within the buffer, an obtainedAt further ahead than the buffer's
			// allowance is never before the end, so this is the one shape left.
			expect(due({ obtainedAt: new Date(NOW + 5000), expiresAt: new Date(NOW + 5000) })).toBe(true);
			expect(due({ obtainedAt: new Date(NOW + 6000), expiresAt: new Date(NOW + 5000) })).toBe(true);
		});
	});
});
