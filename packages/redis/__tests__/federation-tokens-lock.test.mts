/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// D-9 regression: lock release MUST be atomic compare-and-delete. Pre-rename,
// lock.mts release path was GET + DEL, which has a race window during which a
// TTL-expired holder's DEL evicts a freshly-acquired lock owned by a different
// process. Post-rename, the release calls `client.compareAndDelete(key, token)`
// — a single Lua-backed atomic operation that returns `false` when the stored
// value does not match the caller's token, and `del` is never issued.
//
// These tests exercise the release closure produced by `acquireLock` against a
// fake client whose stored value differs from the caller's acquire token.
// Pre-fix: `del` is called regardless. Post-fix: `del` is not called when
// `compareAndDelete` reports no ownership.

import { describe, expect, it, vi } from "vitest";
import { createRedisLock } from "../src/internal/lock.mjs";

describe("D-9 — lock release is atomic compare-and-delete (no spurious DEL)", () => {
	it("release() does NOT call del when compareAndDelete reports value mismatch", async () => {
		const data = new Map<string, string>();
		const delSpy = vi.fn(async (key: string) => {
			if (data.delete(key)) return 1;
			return 0;
		});
		// compareAndDelete: stored value differs from caller's token → returns
		// false. The lock release path MUST honor this (no fallback to plain del).
		const compareAndDeleteSpy = vi.fn(async (key: string, expected: string) => {
			const stored = data.get(key);
			if (stored !== undefined && stored === expected) {
				data.delete(key);
				return true;
			}
			return false;
		});
		const fakeClient = {
			get: async (k: string) => data.get(k) ?? null,
			set: async (k: string, v: string, opts?: { PX?: number; NX?: boolean }) => {
				if (opts?.NX && data.has(k)) return null;
				data.set(k, v);
				return v;
			},
			del: delSpy,
			compareAndDelete: compareAndDeleteSpy,
		};

		const lock = createRedisLock({
			// biome-ignore lint/suspicious/noExplicitAny: fake client structurally satisfies the post-D-9 RedisLockClient shape; the cast keeps the test compatible across the interface widening.
			client: fakeClient as any,
			keyPrefix: "ftlock:",
		});
		const result = await lock.acquireLock({ sid: "sid-1", federationName: "google" });
		expect(result.acquired).toBe(true);

		// Simulate: between acquire and release, another caller overwrote the
		// stored value (TTL expired, B acquired). Replace the stored entry.
		data.set("ftlock:sid-1:google", "interloper-token");

		if (result.acquired) {
			await result.release();
		}

		// Post-fix: compareAndDelete called once, returned false; del NOT called.
		expect(compareAndDeleteSpy).toHaveBeenCalledWith(
			"ftlock:sid-1:google",
			expect.any(String),
		);
		expect(delSpy).not.toHaveBeenCalled();
	});

	it("release() calls compareAndDelete (not GET+DEL) when caller still owns the lock", async () => {
		const data = new Map<string, string>();
		const getSpy = vi.fn(async (k: string) => data.get(k) ?? null);
		const delSpy = vi.fn(async (k: string) => (data.delete(k) ? 1 : 0));
		const compareAndDeleteSpy = vi.fn(async (key: string, expected: string) => {
			if (data.get(key) === expected) {
				data.delete(key);
				return true;
			}
			return false;
		});
		const fakeClient = {
			get: getSpy,
			set: async (k: string, v: string, opts?: { PX?: number; NX?: boolean }) => {
				if (opts?.NX && data.has(k)) return null;
				data.set(k, v);
				return v;
			},
			del: delSpy,
			compareAndDelete: compareAndDeleteSpy,
		};

		const lock = createRedisLock({
			// biome-ignore lint/suspicious/noExplicitAny: see prior test.
			client: fakeClient as any,
			keyPrefix: "ftlock:",
		});
		const result = await lock.acquireLock({ sid: "sid-2", federationName: "google" });
		expect(result.acquired).toBe(true);

		if (result.acquired) {
			await result.release();
		}

		// Post-fix: compareAndDelete is the sole release primitive. The
		// pre-fix GET+DEL release would have called both.
		expect(compareAndDeleteSpy).toHaveBeenCalledTimes(1);
		expect(getSpy).not.toHaveBeenCalled();
		expect(delSpy).not.toHaveBeenCalled();
	});
});
