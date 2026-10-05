/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { setTimeout as sleep } from "node:timers/promises";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisChallengeStore } from "#/challenges.mjs";
import type { ChallengeStoreClient } from "#/clients.mjs";
import { runChallengeStoreContract } from "./adapters.challenge-store.contract.mjs";
import { keysExpire, testRedis } from "./support/redis.mjs";

let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	client = new Redis(at);
});

afterAll(async () => {
	await client?.quit();
});

runChallengeStoreContract(
	"redis",
	{
		create: () => {
			// Per-test prefix isolation so concurrency tests do not collide across
			// shared container state.
			keyCounter += 1;
			return createRedisChallengeStore({
				client: client as unknown as ChallengeStoreClient,
				keyPrefix: `chal:test-${keyCounter}:`,
			});
		},
	},
	{
		// A relative PX: the challenge is gone when its key is.
		expiry: keysExpire(
			() => client,
			() => `chal:test-${keyCounter}:`,
		),
	},
);

describe("redis challenge store — the expiry find reports", () => {
	// A reply that reaches the adapter late: Redis measured the remaining life
	// when it answered, and the answer then spent `REPLY_DELAY_MS` on the way.
	const REPLY_DELAY_MS = 400;
	// PTTL and PX are whole milliseconds on the server's clock.
	const ROUNDING_MS = 2;

	it("is no later than the issued expiry, beyond the write's own latency, however slow the PTTL reply", async () => {
		keyCounter += 1;
		const keyPrefix = `chal:slow-reply-${keyCounter}:`;
		const slowReplies: ChallengeStoreClient = {
			set: (...args) => (client as unknown as ChallengeStoreClient).set(...args),
			del: (key) => client.del(key),
			pttl: async (key) => {
				const remaining = await client.pttl(key);
				await sleep(REPLY_DELAY_MS);
				return remaining;
			},
		};
		const store = createRedisChallengeStore({ client: slowReplies, keyPrefix });

		const issueStartedAtMs = Date.now();
		const issuedExpiryMs = issueStartedAtMs + 60_000;
		await store.issue("webauthn:authentication", "slow-reply", issuedExpiryMs);
		// The key's life is measured from when Redis received the write, no later than this.
		const writeLatencyMs = Date.now() - issueStartedAtMs;

		const found = await store.find("webauthn:authentication", "slow-reply");

		expect(found).not.toBeNull();
		expect(found?.expiresAtMs).toBeLessThanOrEqual(issuedExpiryMs + writeLatencyMs + ROUNDING_MS);
		// Not absurdly early either: at most the reply's delay and the write's latency before it.
		expect(found?.expiresAtMs).toBeGreaterThanOrEqual(
			issuedExpiryMs - REPLY_DELAY_MS - writeLatencyMs - 100,
		);
	});
});
