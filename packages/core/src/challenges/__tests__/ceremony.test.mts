/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it, vi } from "vitest";
import { createMemoryReplaySeenSet } from "../../replay-seen-set/adapters/memory.mjs";
import type { ReplaySeenSet } from "../../replay-seen-set/types.mjs";
import { createMemoryChallengeStore } from "../adapters/memory.mjs";
import { createDefaultChallengeCeremony } from "../ceremony.mjs";
import { ChallengeStorageError } from "../errors.mjs";

const future = (): Date => new Date(Date.now() + 60_000);

function makeCeremonyWithMemoryBackends() {
	const store = createMemoryChallengeStore();
	const set = createMemoryReplaySeenSet();
	return {
		store,
		set,
		ceremony: createDefaultChallengeCeremony({ challengeStore: store, replaySeenSet: set }),
	};
}

describe("createDefaultChallengeCeremony — 3-outcome path (memory backends)", () => {
	it("never-issued → outcome 'unknown'", async () => {
		const { ceremony } = makeCeremonyWithMemoryBackends();
		const result = await ceremony.consume("scope-A", "never-existed");
		expect(result).toEqual({ outcome: "unknown" });
	});

	it("issued + first consume → outcome 'consumed'; replaySeenSet records the entry; outcome object is frozen", async () => {
		const { store, set, ceremony } = makeCeremonyWithMemoryBackends();
		await store.issue("scope-A", "v", future());
		const result = await ceremony.consume("scope-A", "v");
		expect(result).toEqual({ outcome: "consumed" });
		expect(await set.contains("scope-A", "v")).toBe(true);
		// Anchor the runtime-freeze contract: a future refactor that drops
		// Object.freeze while keeping `as const` would still type-check but
		// silently weaken immutability. Per Task 5 reviewer P5 (advisory).
		expect(Object.isFrozen(result)).toBe(true);
	});

	it("consumed once + second consume → outcome 'replayed'", async () => {
		const { store, ceremony } = makeCeremonyWithMemoryBackends();
		await store.issue("scope-A", "v", future());
		await ceremony.consume("scope-A", "v"); // outcome consumed
		const result = await ceremony.consume("scope-A", "v");
		expect(result).toEqual({ outcome: "replayed" });
	});

	it("race-loss path: 2 concurrent consume on one issued challenge → 1 'consumed' + 1 'replayed'", async () => {
		const { store, ceremony } = makeCeremonyWithMemoryBackends();
		await store.issue("scope-A", "race", future());
		const [a, b] = await Promise.all([
			ceremony.consume("scope-A", "race"),
			ceremony.consume("scope-A", "race"),
		]);
		const outcomes = [a.outcome, b.outcome].sort();
		expect(outcomes).toEqual(["consumed", "replayed"]);
	});

	it("TTL-elapsed path: issue + wait > TTL → outcome 'unknown' (replay window closed)", async () => {
		const { store, ceremony } = makeCeremonyWithMemoryBackends();
		await store.issue("scope-A", "expires", new Date(Date.now() + 50));
		await new Promise((r) => setTimeout(r, 100));
		const result = await ceremony.consume("scope-A", "expires");
		expect(result).toEqual({ outcome: "unknown" });
	});

	it("markSeen race swallow: markSeen throws 'expired-at-issue' but consume succeeded → outcome stays 'consumed'", async () => {
		const store = createMemoryChallengeStore();
		// Mock replaySeenSet that throws expired-at-issue from markSeen.
		const set: ReplaySeenSet = {
			kind: "mock",
			markSeen: vi.fn(async () => {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}),
			contains: vi.fn(async () => false),
		};
		const ceremony = createDefaultChallengeCeremony({ challengeStore: store, replaySeenSet: set });
		await store.issue("scope-A", "race-ttl", future());
		const result = await ceremony.consume("scope-A", "race-ttl");
		expect(result).toEqual({ outcome: "consumed" });
		expect(set.markSeen).toHaveBeenCalledOnce();
	});

	it("markSeen non-expired-at-issue errors propagate (NOT swallowed)", async () => {
		const store = createMemoryChallengeStore();
		const innerError = new Error("redis network down");
		const set: ReplaySeenSet = {
			kind: "mock",
			markSeen: vi.fn(async () => {
				throw innerError;
			}),
			contains: vi.fn(async () => false),
		};
		const ceremony = createDefaultChallengeCeremony({ challengeStore: store, replaySeenSet: set });
		await store.issue("scope-A", "system-err", future());
		await expect(ceremony.consume("scope-A", "system-err")).rejects.toBe(innerError);
	});

	it("concurrency property (N=30): exactly 1 'consumed', remaining are 'replayed' or 'unknown' (per §6.1 propagation gap)", async () => {
		// Per master roadmap §3.6: assert single winner + zero false accepts ONLY.
		// Do NOT assert exact replayed/unknown split — timing-dependent.
		const { store, ceremony } = makeCeremonyWithMemoryBackends();
		await store.issue("scope-A", "swarm", future());
		const N = 30;
		const results = await Promise.all(
			Array.from({ length: N }, () => ceremony.consume("scope-A", "swarm")),
		);
		const consumed = results.filter((r) => r.outcome === "consumed").length;
		expect(consumed).toBe(1);
		// Remaining N-1 split between "replayed" and "unknown" — exact split is
		// timing-dependent and NOT asserted per §6.1.
		const others = results.filter((r) => r.outcome !== "consumed").length;
		expect(others).toBe(N - 1);
	});
});
