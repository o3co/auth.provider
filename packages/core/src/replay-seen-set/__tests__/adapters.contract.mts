/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { ChallengeStorageError } from "../../challenges/errors.mjs";
import type { ReplaySeenSet } from "../types.mjs";

export interface ReplaySeenSetContractFactory {
	create(): Promise<ReplaySeenSet> | ReplaySeenSet;
	teardown?(set: ReplaySeenSet): Promise<void> | void;
}

/**
 * Adapter contract suite for ReplaySeenSet. Memory + Redis adapters both
 * call this and MUST pass identically.
 *
 * Per A1 §13.1 + master roadmap §3.6.
 */
export function runReplaySeenSetContract(
	factoryName: string,
	factory: ReplaySeenSetContractFactory,
): void {
	describe(`ReplaySeenSet contract — ${factoryName}`, () => {
		const future = (): Date => new Date(Date.now() + 60_000);

		async function withSet(body: (set: ReplaySeenSet) => Promise<void>): Promise<void> {
			const set = await factory.create();
			try {
				await body(set);
			} finally {
				await factory.teardown?.(set);
			}
		}

		it("markSeen returns true on first call, false on replay", async () => {
			await withSet(async (set) => {
				expect(await set.markSeen("scope-A", "k1", future())).toBe(true);
				expect(await set.markSeen("scope-A", "k1", future())).toBe(false);
			});
		});

		it("contains returns false before markSeen, true after", async () => {
			await withSet(async (set) => {
				expect(await set.contains("scope-A", "k2")).toBe(false);
				await set.markSeen("scope-A", "k2", future());
				expect(await set.contains("scope-A", "k2")).toBe(true);
			});
		});

		it("markSeen throws 'expired-at-issue' for past expiresAt", async () => {
			await withSet(async (set) => {
				const past = new Date(Date.now() - 1_000);
				await expect(set.markSeen("scope-A", "k3", past)).rejects.toMatchObject({
					name: "ChallengeStorageError",
					reason: "expired-at-issue",
				});
			});
		});

		it("expired entries treated as absent (contains=false after TTL)", async () => {
			await withSet(async (set) => {
				const soon = new Date(Date.now() + 50);
				await set.markSeen("scope-A", "k4", soon);
				await new Promise((r) => setTimeout(r, 100));
				expect(await set.contains("scope-A", "k4")).toBe(false);
			});
		});

		it("concurrency: N parallel markSeen for same key → exactly 1 returns true", async () => {
			await withSet(async (set) => {
				const N = 50;
				const exp = future();
				const results = await Promise.all(
					Array.from({ length: N }, () => set.markSeen("scope-A", "race", exp)),
				);
				const winners = results.filter((r) => r === true).length;
				expect(winners).toBe(1);
				expect(results.length - winners).toBe(N - 1);
			});
		});

		it("ChallengeStorageError type-import unused-warning guard", () => {
			// Placeholder to anchor the import; vitest will complain if the import
			// is unused above (it's used in the toMatchObject above, kept by ts).
			expect(ChallengeStorageError.name).toBe("ChallengeStorageError");
		});
	});
}
