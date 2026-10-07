/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * `updateFamily`'s compare-and-set holds only on the connection that took the
 * `WATCH`: Redis forgets the watch when that connection closes. A write
 * queued on it must not reach Redis over a replacement connection, where it
 * would land unconditionally over whatever was committed in between — a
 * revocation, for one.
 *
 * Real store, the shipped ioredis client, real Redis: the connection is
 * killed by the server (`CLIENT KILL`) between the read and the `EXEC`.
 */

import { createRefreshTokenFamilyRotation } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RefreshTokenFamilyClient, RefreshTokenFamilyMultiClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "#/refresh-token-family.mjs";
import { testRedis } from "./support/redis.mjs";

/** The name every connection of the client under test carries, duplicates included. */
const UNDER_TEST = "rtfam-connection-loss-under-test";

let io: Redis;
let other: Redis;
let keyCounter = 0;

const FUTURE = (): number => Date.now() + 60_000;

beforeAll(async () => {
	const at = await testRedis();
	io = new Redis({ ...at, connectionName: UNDER_TEST });
	other = new Redis(at);
});

afterAll(async () => {
	io?.disconnect();
	await other?.quit();
});

/** Kills, from the server, every connection the client under test holds. */
async function killConnectionsUnderTest(): Promise<void> {
	const list = String(await other.client("LIST"));
	const ids = list
		.split("\n")
		.filter((line) => line.includes(` name=${UNDER_TEST} `))
		.map((line) => /\bid=(\d+)/.exec(line)?.[1])
		.filter((id): id is string => id !== undefined);
	if (ids.length === 0) throw new Error(`no connection named ${UNDER_TEST} to kill`);
	for (const id of ids) await other.client("KILL", "ID", id);
}

/**
 * The shipped client, with `beforeExec` run once, before the first `EXEC` of
 * a duplicate: after the family was read and the updater decided.
 */
function pausedBeforeFirstExec(
	client: RefreshTokenFamilyClient,
	beforeExec: () => Promise<void>,
): RefreshTokenFamilyClient {
	let ran = false;
	return {
		...client,
		duplicate: () => {
			const conn = client.duplicate();
			return {
				...conn,
				multi: () => {
					const multi = conn.multi();
					const paused: RefreshTokenFamilyMultiClient = {
						set: (key, value, mode, ttlMs) => {
							multi.set(key, value, mode, ttlMs);
							return paused;
						},
						exec: async () => {
							if (!ran) {
								ran = true;
								await beforeExec();
							}
							return multi.exec();
						},
					};
					return paused;
				},
			};
		},
	};
}

describe("updateFamily's compare-and-set does not continue across a connection replacement", () => {
	it("a rotation read before its connection was lost does not overwrite a revocation committed since", async () => {
		const keyPrefix = `rtfam:connection-loss-${++keyCounter}:`;
		const familyId = "fam-1";
		// The revocation, on a connection the kill does not reach.
		const otherStore = await createRedisRefreshTokenFamilyStore({
			client: makeIoredisClients(other).refreshTokenFamilyClient,
			keyPrefix,
		});
		// Set only once the kill and the revocation both happened, so the
		// rejection below is the stale write's, not the pause's.
		let revokedInBetween = false;
		const store = await createRedisRefreshTokenFamilyStore({
			client: pausedBeforeFirstExec(makeIoredisClients(io).refreshTokenFamilyClient, async () => {
				await killConnectionsUnderTest();
				const revoked = await otherStore.updateFamily(familyId, (current) => ({
					action: "commit",
					family: { ...current, revoked: true },
				}));
				revokedInBetween = revoked.outcome === "committed";
			}),
			keyPrefix,
		});
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: 3_600_000,
		});
		await rotation.register("jti-1", familyId, FUTURE());

		await expect(rotation.rotate("jti-1", "jti-2", familyId, FUTURE())).rejects.toThrow();
		expect(revokedInBetween).toBe(true);

		const after = await otherStore.findFamily(familyId);
		expect(after?.revoked).toBe(true);
		expect(after?.activeJti).toBe("jti-1");
	});

	it("a rotation with no connection loss commits as before", async () => {
		const store = await createRedisRefreshTokenFamilyStore({
			client: makeIoredisClients(io).refreshTokenFamilyClient,
			keyPrefix: `rtfam:connection-loss-${++keyCounter}:`,
		});
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: 3_600_000,
		});
		await rotation.register("jti-1", "fam-1", FUTURE());

		const rotated = await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE());

		expect(rotated.outcome).toBe("rotated");
		const after = await store.findFamily("fam-1");
		expect(after?.revoked).toBe(false);
		expect(after?.activeJti).toBe("jti-2");
	});
});
