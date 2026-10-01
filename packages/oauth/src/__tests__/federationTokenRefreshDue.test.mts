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
});
