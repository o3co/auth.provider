/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { ChallengeStorageError } from "../errors.mjs";
import type { ChallengeStore } from "../types.mjs";

export interface ChallengeStoreContractFactory {
	/** Create a fresh, empty ChallengeStore for one test. */
	create(): Promise<ChallengeStore> | ChallengeStore;
	/** Optional: tear down (close client, flushdb, etc.) after each test. */
	teardown?(store: ChallengeStore): Promise<void> | void;
}

/**
 * Adapter contract suite for ChallengeStore. Memory + Redis adapters both
 * call this and MUST pass identically (parity is the whole point of having
 * two adapters share one contract).
 *
 * Per A1 §13.1 + master roadmap §3.6 (concurrency wording: assert single-
 * winner only; equal-expiry only).
 */
export function runChallengeStoreContract(
	factoryName: string,
	factory: ChallengeStoreContractFactory,
): void {
	describe(`ChallengeStore contract — ${factoryName}`, () => {
		const future = (): number => Date.now() + 60_000;

		async function withStore(body: (store: ChallengeStore) => Promise<void>): Promise<void> {
			const store = await factory.create();
			try {
				await body(store);
			} finally {
				await factory.teardown?.(store);
			}
		}

		it("happy path: issue → find → consume → second consume returns false", async () => {
			await withStore(async (store) => {
				await store.issue("scope-A", "value-1", future());
				const challenge = await store.find("scope-A", "value-1");
				expect(challenge).not.toBeNull();
				expect(typeof challenge?.expiresAtMs).toBe("number");
				expect(await store.consume("scope-A", "value-1")).toBe(true);
				expect(await store.consume("scope-A", "value-1")).toBe(false);
			});
		});

		it("issue throws 'duplicate' on existing non-expired entry", async () => {
			await withStore(async (store) => {
				await store.issue("scope-A", "v", future());
				await expect(store.issue("scope-A", "v", future())).rejects.toMatchObject({
					name: "ChallengeStorageError",
					reason: "duplicate",
				});
			});
		});

		it("issue throws 'expired-at-issue' for expiresAtMs <= now()", async () => {
			await withStore(async (store) => {
				const past = Date.now() - 1_000;
				await expect(store.issue("scope-A", "v", past)).rejects.toBeInstanceOf(
					ChallengeStorageError,
				);
				await expect(store.issue("scope-A", "v", past)).rejects.toMatchObject({
					reason: "expired-at-issue",
				});
			});
		});

		it("issue refuses an expiry that is not a finite number, and records nothing", async () => {
			// NaN is never `<= now`, so it slipped past the expired-at-issue check:
			// the memory adapter kept the challenge forever (and `find` answered
			// `expiresAtMs: NaN`), and Redis was sent `PX NaN`. A non-finite expiry
			// is a caller fault, not the timing race `expired-at-issue` names.
			await withStore(async (store) => {
				for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
					await expect(store.issue("scope-A", "v-bad", bad)).rejects.toThrow(RangeError);
					expect(await store.find("scope-A", "v-bad")).toBeNull();
				}
				// Nothing was recorded, so this is not a duplicate.
				await store.issue("scope-A", "v-bad", future());
				expect(await store.consume("scope-A", "v-bad")).toBe(true);
			});
		});

		it("issue accepts a fractional expiry, and keeps the challenge at least until it", async () => {
			// A lifetime configured in fractional milliseconds or seconds makes
			// one. Redis's PX takes whole milliseconds, so an adapter rounds the
			// challenge's life up, never down.
			await withStore(async (store) => {
				await store.issue("scope-A", "v-frac", Date.now() + 60_000.5);
				const challenge = await store.find("scope-A", "v-frac");
				expect(challenge?.expiresAtMs).toBeGreaterThan(Date.now() + 59_000);
				await expect(store.issue("scope-A", "v-frac", future())).rejects.toMatchObject({
					reason: "duplicate",
				});
				expect(await store.consume("scope-A", "v-frac")).toBe(true);
			});
		});

		it("find returns null for nonexistent entries", async () => {
			await withStore(async (store) => {
				expect(await store.find("scope-A", "nope")).toBeNull();
			});
		});

		it("consume returns false for nonexistent entries", async () => {
			await withStore(async (store) => {
				expect(await store.consume("scope-A", "nope")).toBe(false);
			});
		});

		it("expired entries are treated as nonexistent (find=null, consume=false)", async () => {
			await withStore(async (store) => {
				const soon = Date.now() + 50;
				await store.issue("scope-A", "ttl", soon);
				await new Promise((r) => setTimeout(r, 100));
				expect(await store.find("scope-A", "ttl")).toBeNull();
				expect(await store.consume("scope-A", "ttl")).toBe(false);
			});
		});

		it("scope isolation — same value in different scopes do not collide", async () => {
			await withStore(async (store) => {
				await store.issue("scope-A", "v", future());
				await store.issue("scope-B", "v", future());
				expect(await store.consume("scope-A", "v")).toBe(true);
				expect(await store.consume("scope-B", "v")).toBe(true);
			});
		});

		it("delimiter-collision-safe: ('ab','cd') ≠ ('abcd','')", async () => {
			await withStore(async (store) => {
				await store.issue("ab", "cd", future());
				await store.issue("abcd", "", future());
				expect(await store.consume("ab", "cd")).toBe(true);
				expect(await store.consume("abcd", "")).toBe(true);
			});
		});

		it("concurrency: N parallel consume on one entry → exactly 1 returns true", async () => {
			await withStore(async (store) => {
				await store.issue("scope-A", "race", future());
				const N = 50;
				const results = await Promise.all(
					Array.from({ length: N }, () => store.consume("scope-A", "race")),
				);
				const winners = results.filter((r) => r === true).length;
				expect(winners).toBe(1);
				expect(results.length - winners).toBe(N - 1);
			});
		});
	});
}
