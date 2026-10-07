/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The family's absolute expiry, against a real Redis whose replies arrive
 * late: the store answers the expiry it stored, so no reply latency moves the
 * cap the rotation wrapper commits, however many rotations run; and a record
 * read after its stored expiry, while its key still lives, is still revoked
 * and never re-extended.
 */

import { setTimeout as sleep } from "node:timers/promises";
import {
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	type RefreshTokenFamilyStore,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "#/refresh-token-family.mjs";
import { testRedis } from "./support/redis.mjs";

/** How late every read's reply reaches the adapter. */
const REPLY_DELAY_MS = 250;
const ROTATIONS = 4;

let client: Redis;
let keyCounter = 0;

beforeAll(async () => {
	const at = await testRedis();
	client = new Redis(at);
});

afterAll(async () => {
	await client?.quit();
});

const late = async <T,>(reply: Promise<T>): Promise<T> => {
	const value = await reply;
	await sleep(REPLY_DELAY_MS);
	return value;
};

/** The shipped client, with every read's and every commit's reply delayed after Redis answered. */
function slowReplies(base: RefreshTokenFamilyClient): RefreshTokenFamilyClient {
	const slowMulti = (multi: RefreshTokenFamilyMultiClient): RefreshTokenFamilyMultiClient => ({
		set(...args) {
			multi.set(...args);
			return this;
		},
		exec: () => late(multi.exec()),
	});
	const slowConnection = (
		conn: DisposableRefreshTokenFamilyClient,
	): DisposableRefreshTokenFamilyClient => ({
		set: (...args) => conn.set(...args),
		get: (key) => late(conn.get(key)),
		pttl: (key) => late(conn.pttl(key)),
		watch: (...keys) => conn.watch(...keys),
		unwatch: () => conn.unwatch(),
		multi: () => slowMulti(conn.multi()),
		duplicate: () => slowConnection(conn.duplicate()),
		durability: () => conn.durability(),
		[Symbol.asyncDispose]: () => conn[Symbol.asyncDispose](),
	});
	return {
		set: (...args) => base.set(...args),
		get: (key) => late(base.get(key)),
		pttl: (key) => late(base.pttl(key)),
		watch: (...keys) => base.watch(...keys),
		unwatch: () => base.unwatch(),
		multi: () => slowMulti(base.multi()),
		duplicate: () => slowConnection(base.duplicate()),
		durability: () => base.durability(),
	};
}

async function store(): Promise<{ store: RefreshTokenFamilyStore; keyPrefix: string }> {
	keyCounter += 1;
	const keyPrefix = `rtfam:expiry-${keyCounter}:`;
	return {
		keyPrefix,
		store: await createRedisRefreshTokenFamilyStore({
			client: slowReplies(makeIoredisClients(client).refreshTokenFamilyClient),
			keyPrefix,
		}),
	};
}

describe("redis refresh-token family — the absolute expiry across slow replies", () => {
	it("never moves the family's cap later, however many rotations run", async () => {
		const { store: familyStore, keyPrefix } = await store();
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: familyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		const capMs = Date.now() + 60_000;
		await rotation.register("jti-0", "fam", capMs);

		for (let i = 1; i <= ROTATIONS; i++) {
			// Each rotation asks for more than the cap; the cap is what it gets.
			const result = await rotation.rotate(`jti-${i - 1}`, `jti-${i}`, "fam", Date.now() + 600_000);
			if (result.outcome !== "rotated") throw new Error(`rotation ${i}: ${result.outcome}`);
			expect(result.cappedExpiresAtMs).toBe(capMs);
		}

		expect((await familyStore.findFamily("fam"))?.expiresAtMs).toBe(capMs);
		// The key itself outlives the cap by no more than the writes' own latency.
		const pttl = await client.pttl(`${keyPrefix}fam`);
		expect(Date.now() + pttl).toBeLessThanOrEqual(capMs + 50);
	}, 30_000);

	it("still revokes, and never re-extends, a family read after its stored expiry while its key lives", async () => {
		const { store: familyStore, keyPrefix } = await store();
		const storedExpiryMs = Date.now() - 1_000;
		const lingering = () =>
			client.set(
				`${keyPrefix}fam-past`,
				JSON.stringify({
					familyId: "fam-past",
					activeJti: "jti",
					revoked: false,
					expiresAtMs: storedExpiryMs,
				}),
				"PX",
				60_000,
			);
		await lingering();

		// Answered as stored, not rebuilt from the key's remaining life.
		expect((await familyStore.findFamily("fam-past"))?.expiresAtMs).toBe(storedExpiryMs);

		// A rotation cannot commit past the cap.
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: familyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		await expect(
			rotation.rotate("jti", "jti-next", "fam-past", Date.now() + 600_000),
		).rejects.toMatchObject({ reason: "expired-at-issue" });

		// A revocation still lands.
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: familyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		await revocation.revokeFamily("fam-past");
		expect(await revocation.isFamilyRevoked("fam-past")).toBe(true);
	});
});
