/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Which way the adapters round a record's remaining life for `PX`.
 *
 * `PX` takes whole milliseconds, so a fractional expiry has to be rounded, and
 * only one direction is safe: up. A record whose life is rounded down dies
 * before the instant its caller asked for — a replay record before the proof
 * stops being acceptable, a revocation before the token expires. The contract
 * suites cannot tell `Math.ceil` from `Math.round` against a real Redis (the
 * difference is under a millisecond), so a recording client pins it: the `PX`
 * each adapter sends is a whole number no smaller than the life it was asked
 * for, on a clock frozen so that life is exact.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRedisAccessTokenDenylist } from "../src/access-token-denylist.mjs";
import { createRedisChallengeStore } from "../src/challenges.mjs";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	ReplaySeenSetClient,
} from "../src/clients.mjs";
import { createRedisReplaySeenSet } from "../src/replay-seen-set.mjs";

const NOW = Date.UTC(2026, 8, 24, 12, 0, 0);

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(NOW);
});

afterEach(() => {
	vi.useRealTimers();
});

/** Records every `PX` a `SET` is sent with. */
const recorder = () => {
	const px: number[] = [];
	const set = async (_key: string, _value: string, _mode: "PX", ttlMs: number) => {
		px.push(ttlMs);
		return "OK" as const;
	};
	return { px, set };
};

/** Lives whose rounding differs by direction: .4 rounds down under Math.round, .5 up. */
const FRACTIONAL_LIVES = [1_234.4, 1_234.5, 0.2, 59_999.999];

const expectRoundedUp = (sent: number[], lives: readonly number[]) => {
	expect(sent).toHaveLength(lives.length);
	sent.forEach((px, i) => {
		const life = lives[i] as number;
		expect(Number.isInteger(px), `PX ${px} for a life of ${life} ms`).toBe(true);
		expect(px, `PX ${px} for a life of ${life} ms`).toBeGreaterThanOrEqual(life);
		expect(px - life, `PX ${px} for a life of ${life} ms`).toBeLessThan(1);
	});
};

describe("the PX an adapter sends is its record's life, rounded up to a whole millisecond", () => {
	it("ReplaySeenSet.markSeen", async () => {
		const client = recorder();
		const set = createRedisReplaySeenSet({
			client: { set: client.set, exists: async () => 0 } as ReplaySeenSetClient,
			keyPrefix: "replay:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await set.markSeen("scope", `k${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});

	it("ChallengeStore.issue", async () => {
		const client = recorder();
		const store = createRedisChallengeStore({
			client: {
				set: client.set,
				pttl: async () => -2,
				del: async () => 0,
			} as ChallengeStoreClient,
			keyPrefix: "chal:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await store.issue("scope", `v${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});

	it("AccessTokenDenylist.add", async () => {
		const client = recorder();
		const denylist = createRedisAccessTokenDenylist({
			client: { set: client.set, exists: async () => 0 } as AccessTokenDenylistClient,
			keyPrefix: "atdeny:",
		});
		for (const [i, life] of FRACTIONAL_LIVES.entries()) {
			await denylist.add(`j${i}`, NOW + life);
		}
		expectRoundedUp(client.px, FRACTIONAL_LIVES);
	});
});
