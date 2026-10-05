/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { setTimeout as sleep } from "node:timers/promises";
import { canonicalChallengeKey } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createRedisChallengeStore } from "#/challenges.mjs";
import type { ChallengeStoreClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
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

describe("redis challenge store — the issuance it records", () => {
	const SCOPE = "webauthn:authentication";
	// The client a deployment runs.
	const ioredis = (): ChallengeStoreClient => makeIoredisClients(client).challengeStoreClient;

	function freshStore(over: Partial<ChallengeStoreClient> = {}) {
		keyCounter += 1;
		const keyPrefix = `chal:issued-${keyCounter}:`;
		return {
			keyPrefix,
			store: createRedisChallengeStore({ client: { ...ioredis(), ...over }, keyPrefix }),
		};
	}

	for (const [label, stored] of [
		["the value written before the upgrade", "1"],
		["a value in no form the store writes", "i:not-a-number"],
		["an issuance that is not finite", "i:Infinity"],
		["an empty issuance", "i:"],
		["an issuance in a form the store never writes", "i:0x10"],
	] as const) {
		it(`answers no issuance for a live key holding ${label}`, async () => {
			const { store, keyPrefix } = freshStore();
			await client.set(`${keyPrefix}${canonicalChallengeKey(SCOPE, "v")}`, stored, "PX", 60_000);

			const found = await store.find(SCOPE, "v");

			expect(found).not.toBeNull();
			expect(found?.issuedAtMs).toBeUndefined();
		});
	}

	it("answers no issuance through a client without `get`, and still answers the challenge", async () => {
		const { get: _get, ...withoutGet } = ioredis() as ChallengeStoreClient & { get?: unknown };
		keyCounter += 1;
		const store = createRedisChallengeStore({
			client: withoutGet as ChallengeStoreClient,
			keyPrefix: `chal:no-get-${keyCounter}:`,
		});
		const issuedAtMs = Date.now();
		await store.issue(SCOPE, "v", issuedAtMs + 60_000, issuedAtMs);

		const found = await store.find(SCOPE, "v");

		expect(found).not.toBeNull();
		expect(found?.issuedAtMs).toBeUndefined();
	});

	it("refuses a bad issuance before asking Redis anything", async () => {
		const set = vi.fn(ioredis().set);
		const { store } = freshStore({ set });

		await expect(store.issue(SCOPE, "v", Date.now() + 60_000, Number.NaN)).rejects.toThrow(
			RangeError,
		);

		expect(set).not.toHaveBeenCalled();
	});
});
