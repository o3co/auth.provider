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
