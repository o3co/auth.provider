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
 * The floor under the versions the Store answers, kept in the provider's
 * seen-set: within its horizon after a write through this provider, a record
 * is admitted only at the version last written — one written earlier, however
 * many writes back, is refused — and at most two horizons after the last
 * write, any version is admitted again. It holds across a bucket boundary
 * and between replicas whose clocks differ by less than the horizon, keeps
 * neither the subject nor the factor id in a key, and throws when the
 * seen-set cannot record or answer.
 */

import { createMemoryReplaySeenSet, type ReplaySeenSet } from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createMfaFactorVersionFloor,
	MFA_FACTOR_VERSION_FLOOR_HORIZON_MS,
} from "#/mfa/versionFloor.mjs";

const H = MFA_FACTOR_VERSION_FLOOR_HORIZON_MS;
const ID = "u1PIlRkb_cy7UmjYUKaL_A";
/** The start of a bucket, well after the real clock, so every mark lies ahead of it. */
const T0 = (Math.floor(Date.now() / H) + 10) * H;

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(T0);
});
afterEach(() => {
	vi.useRealTimers();
});

const at = (ms: number) => vi.setSystemTime(ms);

describe("the version floor", () => {
	it("keeps its marks at least as long as a TOTP step can be answered again: its horizon is 30 minutes", () => {
		// The longest acceptance span the TOTP factor's settings allow is five
		// steps of 120 seconds (a window of two either side of now).
		expect(H).toBe(30 * 60 * 1000);
		expect(H).toBeGreaterThan(5 * 120 * 1000);
	});

	it("admits any version of a record nothing wrote through it", async () => {
		const floor = createMfaFactorVersionFloor(createMemoryReplaySeenSet());
		for (const version of [0, 1, 7]) expect(await floor.admits("user-1", ID, version)).toBe(true);
	});

	it("admits the version last written and refuses an older one, and other records are not held to it", async () => {
		const floor = createMfaFactorVersionFloor(createMemoryReplaySeenSet());
		await floor.wrote("user-1", ID, 2);
		expect(await floor.admits("user-1", ID, 2)).toBe(true);
		expect(await floor.admits("user-1", ID, 1)).toBe(false);
		expect(await floor.admits("user-1", "v2QJmSlc-dz8VnkZVLbM_B", 1)).toBe(true);
		expect(await floor.admits("user-2", ID, 1)).toBe(true);
	});

	it("refuses a version written before the last, however many writes back and however long ago it was written", async () => {
		const floor = createMfaFactorVersionFloor(createMemoryReplaySeenSet());
		await floor.wrote("user-1", ID, 2);
		at(T0 + 5 * H);
		await floor.wrote("user-1", ID, 3);
		await floor.wrote("user-1", ID, 4);
		for (const version of [1, 2, 3]) {
			expect(await floor.admits("user-1", ID, version), String(version)).toBe(false);
		}
		expect(await floor.admits("user-1", ID, 4)).toBe(true);
	});

	it("holds for at least the horizon after a write, wherever in its bucket the write falls", async () => {
		for (const offset of [0, 1, H / 2, H - 1]) {
			const floor = createMfaFactorVersionFloor(createMemoryReplaySeenSet());
			at(T0 + offset);
			await floor.wrote("user-1", ID, 2);
			at(T0 + offset + H - 1);
			expect(await floor.admits("user-1", ID, 1), String(offset)).toBe(false);
			expect(await floor.admits("user-1", ID, 2), String(offset)).toBe(true);
		}
	});

	it("admits any version again at most two horizons after the last write", async () => {
		for (const offset of [0, H - 1]) {
			const floor = createMfaFactorVersionFloor(createMemoryReplaySeenSet());
			at(T0 + offset);
			await floor.wrote("user-1", ID, 2);
			at(T0 + 2 * H);
			expect(await floor.admits("user-1", ID, 1), String(offset)).toBe(true);
			expect(await floor.admits("user-1", ID, 2), String(offset)).toBe(true);
		}
	});

	it("holds between replicas whose clocks differ by less than the horizon, either way", async () => {
		for (const skew of [H / 2, -H / 2, 1, -1]) {
			const seen = createMemoryReplaySeenSet();
			const writer = createMfaFactorVersionFloor(seen);
			const reader = createMfaFactorVersionFloor(seen, { now: () => Date.now() + skew });
			await writer.wrote("user-1", ID, 2);
			expect(await reader.admits("user-1", ID, 1), String(skew)).toBe(false);
			expect(await reader.admits("user-1", ID, 2), String(skew)).toBe(true);
		}
	});

	it("keys its marks by neither the subject nor the factor id, each within a bounded length", async () => {
		const keys: string[] = [];
		const inner = createMemoryReplaySeenSet();
		const seen: ReplaySeenSet = {
			kind: "recording",
			markSeen: (scope, key, expiresAtMs) => {
				keys.push(`${scope}|${key}`);
				return inner.markSeen(scope, key, expiresAtMs);
			},
			contains: (scope, key) => {
				keys.push(`${scope}|${key}`);
				return inner.contains(scope, key);
			},
		};
		const floor = createMfaFactorVersionFloor(seen);
		const subject = `user-${"s".repeat(4096)}`;
		await floor.wrote(subject, ID, 2);
		await floor.admits(subject, ID, 1);
		expect(keys.length).toBeGreaterThan(0);
		for (const key of keys) {
			expect(key).not.toContain("user-");
			expect(key).not.toContain(ID);
			expect(key.length).toBeLessThan(128);
		}
	});

	it("throws when the seen-set cannot record a write or answer a read", async () => {
		const down: ReplaySeenSet = {
			kind: "down",
			markSeen: async () => {
				throw new Error("seen-set unavailable");
			},
			contains: async () => {
				throw new Error("seen-set unavailable");
			},
		};
		const floor = createMfaFactorVersionFloor(down);
		await expect(floor.wrote("user-1", ID, 2)).rejects.toThrow("seen-set unavailable");
		await expect(floor.admits("user-1", ID, 1)).rejects.toThrow("seen-set unavailable");
	});
});
