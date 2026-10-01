/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// Lock release MUST be an atomic compare-and-delete. A GET + DEL release has a
// window in which a TTL-expired holder's DEL evicts a lock another process has
// just acquired. The release calls `client.compareAndDelete(key, token)`, one
// Lua-backed operation that returns `false` when the stored value is not the
// caller's token, and never issues `del`.
//
// These tests run the release closure from `acquireLock` against a fake
// client; `del` is not called when `compareAndDelete` reports no ownership.

import { describe, expect, it, vi } from "vitest";
import { createRedisLock } from "#/internal/lock.mjs";

describe("lock release is atomic compare-and-delete (no spurious DEL)", () => {
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
			client: fakeClient,
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

		// compareAndDelete called once and returned false; del NOT called.
		expect(compareAndDeleteSpy).toHaveBeenCalledWith("ftlock:sid-1:google", expect.any(String));
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
			client: fakeClient,
			keyPrefix: "ftlock:",
		});
		const result = await lock.acquireLock({ sid: "sid-2", federationName: "google" });
		expect(result.acquired).toBe(true);

		if (result.acquired) {
			await result.release();
		}

		// compareAndDelete is the sole release primitive: no GET, no DEL.
		expect(compareAndDeleteSpy).toHaveBeenCalledTimes(1);
		expect(getSpy).not.toHaveBeenCalled();
		expect(delSpy).not.toHaveBeenCalled();
	});
});
