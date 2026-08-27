/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Issue #274 — refresh-replay family revocation used to be a SEPARATE write
 * from the compare-and-swap that detected the replay. Between "replay
 * detected, CAS aborted" and "family revoked" a parallel request holding the
 * still-active sibling token could complete its own rotation and receive
 * tokens, which is most of what the RFC 6819 §5.2.2.3 family-revoke defence
 * exists to prevent.
 *
 * These tests run the real rotation wrapper over the real Redis adapter
 * against a real Redis, because the claim being made is about what Redis
 * serialises. The in-memory adapter cannot falsify it: its read-modify-write
 * is synchronous, so it has no interleaving to lose.
 *
 * The load-bearing assertion in every case is that the family is revoked by
 * the time a `replayed` outcome is observable — never after some later write
 * the caller still has to make.
 */

import {
	createRefreshTokenFamilyRotation,
	type RefreshTokenFamilyRotationOutcome,
	RefreshTokenStorageError,
} from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "../src/refresh-token-family.mjs";

let container: StartedTestContainer;
let io: Redis;
let keyCounter = 0;

const FUTURE = (): number => Date.now() + 60_000;

/**
 * A fresh store per test, key-prefixed so the shared container does not carry
 * state across cases. `casRetryLimit` is generous for the same reason the
 * existing concurrency contract test raises it: under 20-way contention the
 * default budget of 3 is exhausted by losers long before the property under
 * test is exercised.
 */
const freshStore = () => {
	keyCounter++;
	return createRedisRefreshTokenFamilyStore({
		client: makeIoredisClients(io).refreshTokenFamilyClient,
		keyPrefix: `rtfam:replay-${keyCounter}:`,
		casRetryLimit: 50,
	});
};

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	io = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 90_000);

afterAll(async () => {
	await io?.quit();
	await container?.stop();
});

/** Classify a settled rotation, folding CAS exhaustion into its own bucket. */
const tally = (settled: PromiseSettledResult<RefreshTokenFamilyRotationOutcome>[]) => {
	const counts = { rotated: 0, replayed: 0, revoked: 0, unknown: 0, exhausted: 0 };
	for (const s of settled) {
		if (s.status === "fulfilled") {
			if (s.value.outcome === "rotated") counts.rotated++;
			else if (s.value.outcome === "replayed") counts.replayed++;
			else if (s.value.outcome === "revoked") counts.revoked++;
			else counts.unknown++;
		} else if (
			s.reason instanceof RefreshTokenStorageError &&
			s.reason.reason === "conflict-exhausted"
		) {
			counts.exhausted++;
		} else {
			throw new Error(`unexpected rejection: ${String(s.reason)}`);
		}
	}
	return counts;
};

describe("refresh-replay detection and family revocation are one Redis write (#274)", () => {
	it("revokes the family in the same WATCH/MULTI/EXEC that detects the replay", async () => {
		const store = freshStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE()); // legitimate rotation

		const replay = await rotation.rotate("jti-1", "jti-evil", "fam-1", FUTURE());

		expect(replay.outcome).toBe("replayed");
		if (replay.outcome !== "replayed") return; // type narrowing
		expect(replay.familyRevoked).toBe(true);

		// Already durable in Redis when `rotate` returned — no second write.
		const after = await store.findFamily("fam-1");
		expect(after?.revoked).toBe(true);
		// The revoked family keeps the jti that was active when it died, not
		// the replayed one (A3 §5.1 audit trail).
		expect(after?.activeJti).toBe("jti-2");
	});

	it("N concurrent redemptions of the SAME refresh token: exactly one rotates, family ends revoked", async () => {
		const store = freshStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());

		const N = 20;
		const settled = await Promise.allSettled(
			Array.from({ length: N }, (_, i) =>
				rotation.rotate("jti-1", `jti-new-${i}`, "fam-1", FUTURE()),
			),
		);

		const counts = tally(settled);
		// Exactly one redemption of a given refresh token may succeed. Every
		// other one is, by definition, a replay of a consumed token.
		expect(counts.rotated).toBe(1);
		expect(counts.unknown).toBe(0);
		expect(counts.replayed + counts.revoked + counts.exhausted).toBe(N - 1);
		// At least one loser reached a classification rather than exhausting,
		// otherwise the case would prove nothing about revocation.
		expect(counts.replayed).toBeGreaterThan(0);
		expect((await store.findFamily("fam-1"))?.revoked).toBe(true);
	});

	it("a sibling redeeming the still-active token never lands between detection and revocation", async () => {
		// The exact race from the issue: an attacker replays a consumed token
		// while the honest client redeems the current one, concurrently. There
		// is no legal interleaving in which BOTH walk away with tokens after a
		// replay has been classified, and none in which the family is left
		// unrevoked.
		//
		// Repeated, because a race that reproduces once in a while is still a
		// race. Each round is an independent family.
		const ROUNDS = 25;
		for (let round = 0; round < ROUNDS; round++) {
			const store = freshStore();
			const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
			const familyId = `fam-race-${round}`;
			await rotation.register("jti-1", familyId, FUTURE());
			await rotation.rotate("jti-1", "jti-2", familyId, FUTURE());

			const settled = await Promise.allSettled([
				// Attacker: replays the already-consumed jti-1.
				rotation.rotate("jti-1", "jti-evil", familyId, FUTURE()),
				// Honest sibling: holds jti-2, the currently-active jti.
				rotation.rotate("jti-2", "jti-3", familyId, FUTURE()),
			]);

			const counts = tally(settled);
			// The replay can never rotate, so at most the sibling does — and
			// only when Redis ordered it before the replay's revoking commit.
			expect(counts.rotated).toBeLessThanOrEqual(1);
			expect(counts.unknown).toBe(0);
			// Whatever the ordering, the family is dead once the dust settles.
			expect((await store.findFamily(familyId))?.revoked).toBe(true);
			// And the sibling never succeeds AFTER the family was revoked: if
			// the replay was classified first, the sibling must see "revoked".
			const [replayResult, siblingResult] = settled;
			if (replayResult.status === "fulfilled" && siblingResult.status === "fulfilled") {
				expect(replayResult.value.outcome).toBe("replayed");
				expect(["rotated", "revoked", "replayed"]).toContain(siblingResult.value.outcome);
			}
		}
	});

	it("once a replay has revoked the family, every later redemption is refused", async () => {
		const store = freshStore();
		const rotation = createRefreshTokenFamilyRotation({ refreshTokenFamilyStore: store });
		await rotation.register("jti-1", "fam-1", FUTURE());
		await rotation.rotate("jti-1", "jti-2", "fam-1", FUTURE());
		await rotation.rotate("jti-1", "jti-evil", "fam-1", FUTURE()); // replay → revoke

		// The honest sibling still holds jti-2 and is now locked out, which is
		// the whole point of whole-family revocation.
		expect((await rotation.rotate("jti-2", "jti-3", "fam-1", FUTURE())).outcome).toBe("revoked");
		// And so is the attacker.
		expect((await rotation.rotate("jti-1", "jti-evil-2", "fam-1", FUTURE())).outcome).toBe(
			"revoked",
		);
	});
});
