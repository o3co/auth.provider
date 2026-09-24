/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessTokenDenylist } from "../types.mjs";

export interface AccessTokenDenylistContractFactory {
	/** Create a fresh, empty AccessTokenDenylist for one test. */
	create(): Promise<AccessTokenDenylist> | AccessTokenDenylist;
	/** Optional: tear down (close client, flushdb, etc.) after each test. */
	teardown?(store: AccessTokenDenylist): Promise<void> | void;
}

/**
 * Adapter contract suite for AccessTokenDenylist. Memory + Redis adapters both
 * call this and MUST pass identically (parity is the whole point of having
 * two adapters share one contract).
 */
/**
 * Expiries no store may be handed: not finite (NaN, from an Invalid Date or an
 * unset setting; ±Infinity), or outside ECMAScript's Date range (±8.64e15 ms).
 * NaN is never `<= now`, so it slipped past every past-expiry check; one past
 * the Date range is a number Redis cannot take as a deadline (`1e21` is sent
 * as `1e+21`) and a Date cannot hold, and a script that writes its record
 * before setting the deadline left the record with no TTL at all.
 */
const UNSTORABLE_EXPIRIES = [
	Number.NaN,
	Number.POSITIVE_INFINITY,
	Number.NEGATIVE_INFINITY,
	8_640_000_000_000_001,
	1e21,
	-1e21,
];

export function runAccessTokenDenylistContract(
	name: string,
	factory: AccessTokenDenylistContractFactory,
): void {
	describe(`AccessTokenDenylist contract — ${name}`, () => {
		let store: AccessTokenDenylist;

		beforeEach(async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-05-12T00:00:00Z"));
			store = await factory.create();
		});

		afterEach(async () => {
			await factory.teardown?.(store);
			vi.useRealTimers();
		});

		it("declares a non-empty kind", () => {
			expect(store.kind).toBeTruthy();
		});

		it("has returns false for unknown jti", async () => {
			expect(await store.has("never-added")).toBe(false);
		});

		it("has returns true after add", async () => {
			await store.add("j1", Date.now() + 60_000);
			expect(await store.has("j1")).toBe(true);
		});

		it("has returns false after expiry", async () => {
			const exp = Date.now() + 1_000;
			await store.add("j2", exp);
			vi.setSystemTime(new Date(exp + 1));
			expect(await store.has("j2")).toBe(false);
		});

		it("add refuses an expiry that is not a finite number within the Date range, and records nothing", async () => {
			// NaN is never `<= now`: the memory adapter kept such a jti denied
			// forever, beyond the reach of its own sweep, and Redis was sent
			// `PX NaN`. A non-finite expiry is a caller fault.
			for (const bad of UNSTORABLE_EXPIRIES) {
				await expect(store.add("j-bad", bad)).rejects.toThrow(RangeError);
				expect(await store.has("j-bad")).toBe(false);
			}
		});

		it("add accepts a fractional expiry, and denies the jti until it", async () => {
			// A JWT NumericDate may be non-integer (RFC 7519 §2), so `exp * 1000`
			// can be fractional. Redis's PX takes whole milliseconds, so an
			// adapter rounds the entry's life up, never down.
			const exp = Date.now() + 1_000.5;
			await store.add("j-frac", exp);
			expect(await store.has("j-frac")).toBe(true);
			vi.setSystemTime(new Date(Math.ceil(exp) + 1));
			expect(await store.has("j-frac")).toBe(false);
		});

		it("add overwrites expiresAtMs (last-write wins)", async () => {
			const t0 = Date.now();
			await store.add("j3", t0 + 1000);
			await store.add("j3", t0 + 2000);
			vi.setSystemTime(new Date(t0 + 1500));
			expect(await store.has("j3")).toBe(true);
			vi.setSystemTime(new Date(t0 + 2500));
			expect(await store.has("j3")).toBe(false);
		});
	});
}
