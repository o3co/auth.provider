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
	createRefreshBackoff,
	REFRESH_BACKOFF_WINDOW_MS,
} from "#/routes/federationTokenRefreshBackoff.mjs";

const key = (sid: string, accessToken = "at-1", federationName = "google") => ({
	sid,
	federationName,
	accessToken,
});

describe("createRefreshBackoff", () => {
	it("holds a stamped record for the window, and no longer", () => {
		const backoff = createRefreshBackoff();
		backoff.stamp(key("sid-1"), 1_000);

		expect(backoff.holds(key("sid-1"), 1_000)).toBe(true);
		expect(backoff.holds(key("sid-1"), 1_000 + REFRESH_BACKOFF_WINDOW_MS - 1)).toBe(true);
		expect(backoff.holds(key("sid-1"), 1_000 + REFRESH_BACKOFF_WINDOW_MS)).toBe(false);
	});

	it("does not hold a record it never stamped", () => {
		expect(createRefreshBackoff().holds(key("sid-1"), 1_000)).toBe(false);
	});

	it("holds only the same session, federation and access token", () => {
		const backoff = createRefreshBackoff();
		backoff.stamp(key("sid-1"), 1_000);

		expect(backoff.holds(key("sid-2"), 1_000)).toBe(false);
		expect(backoff.holds(key("sid-1", "at-2"), 1_000)).toBe(false);
		expect(backoff.holds(key("sid-1", "at-1", "github"), 1_000)).toBe(false);
	});

	it("does not hold when the clock reads earlier than the stamp", () => {
		const backoff = createRefreshBackoff();
		backoff.stamp(key("sid-1"), 1_000);

		expect(backoff.holds(key("sid-1"), 999)).toBe(false);
	});

	it("restarts the window when the same record is stamped again", () => {
		const backoff = createRefreshBackoff();
		backoff.stamp(key("sid-1"), 1_000);
		backoff.stamp(key("sid-1"), 2_000);

		expect(backoff.holds(key("sid-1"), 1_000 + REFRESH_BACKOFF_WINDOW_MS)).toBe(true);
	});

	it("evicts the oldest stamp beyond its capacity", () => {
		const backoff = createRefreshBackoff({ windowMs: REFRESH_BACKOFF_WINDOW_MS, maxEntries: 2 });
		backoff.stamp(key("sid-1"), 1_000);
		backoff.stamp(key("sid-2"), 1_001);
		backoff.stamp(key("sid-1"), 1_002);
		backoff.stamp(key("sid-3"), 1_003);

		expect(backoff.holds(key("sid-2"), 1_004)).toBe(false);
		expect(backoff.holds(key("sid-1"), 1_004)).toBe(true);
		expect(backoff.holds(key("sid-3"), 1_004)).toBe(true);
	});

	it("keeps no two stamps whose session and federation would join to the same text", () => {
		const backoff = createRefreshBackoff();
		backoff.stamp(key("a", "at-1", "b:c"), 1_000);

		expect(backoff.holds(key("a:b", "at-1", "c"), 1_000)).toBe(false);
	});
});
