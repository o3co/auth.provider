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
