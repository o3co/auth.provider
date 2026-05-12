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
import { createMemoryAccessTokenDenylist } from "../memory.mjs";

describe("createMemoryAccessTokenDenylist", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-05-12T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("kind is 'memory'", () => {
		const store = createMemoryAccessTokenDenylist();
		expect(store.kind).toBe("memory");
	});

	it("has returns false for never-added jti", async () => {
		const store = createMemoryAccessTokenDenylist();
		expect(await store.has("unknown")).toBe(false);
	});

	it("has returns true after add, false after expiry", async () => {
		const store = createMemoryAccessTokenDenylist();
		const expiresAtMs = Date.now() + 60_000;
		await store.add("jti-1", expiresAtMs);
		expect(await store.has("jti-1")).toBe(true);

		vi.setSystemTime(new Date(expiresAtMs + 1));
		expect(await store.has("jti-1")).toBe(false);
	});

	it("add overwrites expiresAtMs on same jti (last-write wins)", async () => {
		const store = createMemoryAccessTokenDenylist();
		const t0 = Date.now();
		await store.add("jti-2", t0 + 1000); // first call: expires at t0+1000
		await store.add("jti-2", t0 + 2000); // second call: expires at t0+2000

		// advance past first expiry but before second
		vi.setSystemTime(new Date(t0 + 1500));
		expect(await store.has("jti-2")).toBe(true); // proves second won

		// advance past second expiry
		vi.setSystemTime(new Date(t0 + 2500));
		expect(await store.has("jti-2")).toBe(false);
	});
});
