/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The Redis `MfaTransactionStore` (the MFA ADR's D8, D21, D25) against core's
 * contract, on a real Redis, and what is Redis-specific below it: the key
 * layout — a hash per transaction expiring at its `expiresAtMs` on the
 * server's clock, a hash per subject for D21's state beside the weekly window
 * as a sorted set of failure times, the email-proof requirement in a key of
 * its own with no TTL — what reclaims the subject state, and what a stored
 * value it cannot read is answered with.
 *
 * Two connections, and the contract's store alternates between them, so the
 * races the suite sets up — N reservations, N consumes, N takes in flight —
 * are races across sockets rather than calls queued on one client. A
 * transaction expires on the server's clock, which is the clock the suite's
 * expiry waits on.
 */

import type {
	MfaLockoutPolicy,
	MfaTransaction,
	MfaTransactionStore,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisMfaTransactionStoreClient } from "#/ioredis.mjs";
import { createRedisMfaTransactionStore } from "#/mfa-transaction-store.mjs";
import { runMfaTransactionStoreContract } from "./adapters.mfa-transaction-store.contract.mjs";
import { serverClock, serverPasses, testRedis } from "./support/redis.mjs";

let connections: Redis[] = [];
let run = 0;

beforeAll(async () => {
	const at = await testRedis();
	connections = [new Redis(at), new Redis(at)];
});

afterAll(async () => {
	await Promise.all(connections.map((connection) => connection.quit()));
});

const first = (): Redis => connections[0] as Redis;

/** How the adapter spells a value inside a key — looked at from outside, as the probes must. */
const keyPart = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/** A keyspace of its own for each case. */
const freshPrefix = (): string => {
	run += 1;
	return `mfat:test-${run}:`;
};

/** One store per connection over one keyspace, every call taken in turn. */
const alternating = (keyPrefix: string): MfaTransactionStore => {
	const stores = connections.map((connection) =>
		createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(connection),
			keyPrefix,
		}),
	);
	let next = 0;
	const pick = (): MfaTransactionStore => {
		const store = stores[next % stores.length] as MfaTransactionStore;
		next += 1;
		return store;
	};
	return {
		kind: "redis",
		create: (tx) => pick().create(tx),
		get: (id) => pick().get(id),
		update: (id, expectedVersion, patch) => pick().update(id, expectedVersion, patch),
		reserveAttempt: (id, max) => pick().reserveAttempt(id, max),
		takeChallenge: (id, expectedVersion) => pick().takeChallenge(id, expectedVersion),
		consume: (id, expectedVersion) => pick().consume(id, expectedVersion),
		reserveSubjectAttempt: (subject, nowMs, policy, browser) =>
			pick().reserveSubjectAttempt(subject, nowMs, policy, browser),
		settleSubjectAttempt: (subject, reservation, outcome) =>
			pick().settleSubjectAttempt(subject, reservation, outcome),
		noteExemptSuccess: (subject, nowMs, policy, browser) =>
			pick().noteExemptSuccess(subject, nowMs, policy, browser),
		clearSubjectState: (subject) => pick().clearSubjectState(subject),
		requireEmailProofAtNextBinding: (subject) => pick().requireEmailProofAtNextBinding(subject),
		emailProofRequiredAtNextBinding: (subject) => pick().emailProofRequiredAtNextBinding(subject),
		consumeEmailProofRequirement: (subject) => pick().consumeEmailProofRequirement(subject),
	};
};

runMfaTransactionStoreContract(async () => alternating(freshPrefix()), {
	expiry: { now: serverClock(first), passed: serverPasses(first) },
});

const MINUTE = 60_000;
const DAY = 86_400_000;
const WEEK = 7 * DAY;

const POLICY: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
	trustedBrowsers: 5,
	trustedBrowserDays: 30,
};

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => {
	const now = Date.now();
	return {
		id: "tx-1",
		purpose: "step_up",
		sessionId: "express-session-1",
		subject: "user-1",
		sid: "sid-1",
		continuation: undefined,
		redirectTo: undefined,
		enrollment: "none",
		emailProof: "not_required",
		acrValues: undefined,
		challenge: undefined,
		pendingEnrollment: undefined,
		attempts: 0,
		sends: 0,
		lastSentAtMs: undefined,
		createdAtMs: now,
		expiresAtMs: now + 10 * MINUTE,
		version: 1,
		...overrides,
	};
};

const storeAt = (keyPrefix: string, connection: Redis = first()): MfaTransactionStore =>
	createRedisMfaTransactionStore({
		client: makeIoredisMfaTransactionStoreClient(connection),
		keyPrefix,
	});

/** The absolute deadline of `key` on the server's clock, in epoch ms; -1 for none, -2 for no key. */
const deadlineOf = async (key: string): Promise<number> =>
	Number(await first().call("PEXPIRETIME", key));

describe("createRedisMfaTransactionStore — the transaction (the MFA ADR's D8)", () => {
	it('declares kind "redis"', () => {
		expect(storeAt(freshPrefix()).kind).toBe("redis");
	});

	it("keeps a transaction in one hash, <prefix>tx:{<id>}, expiring at its expiresAtMs on the server's clock", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const expiresAtMs = Date.now() + 10 * MINUTE + 0.25;
		await store.create(TX({ expiresAtMs }));
		const key = `${prefix}tx:{${keyPart("tx-1")}}`;
		expect(await first().keys(`${prefix}*`)).toEqual([key]);
		expect(await first().type(key)).toBe("hash");
		// Whole milliseconds, rounded up: the key outlives the instant rather
		// than dying before it.
		expect(await deadlineOf(key)).toBe(Math.ceil(expiresAtMs));
		// Neither an update nor a reserved attempt moves the deadline.
		await store.update("tx-1", 1, { sends: 1 });
		await store.reserveAttempt("tx-1", 5);
		expect(await deadlineOf(key)).toBe(Math.ceil(expiresAtMs));
	});

	it("answers a transaction it cannot read back as absent, a consume included", async () => {
		// A transaction is ten minutes of one ceremony: absence fails closed —
		// the user starts again from the password — where an outage would
		// answer 503 until the key expired.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}tx:{${keyPart("tx-1")}}`;
		for (const [field, value] of [
			["record", "not json"],
			["record", JSON.stringify({ purpose: "admin" })],
			["emailProof", '"waived"'],
			["version", "one"],
			["id", "tx-2"],
		] as const) {
			await first().del(key);
			await store.create(TX());
			await first().hset(key, field, value);
			expect(await store.get("tx-1"), `${field}=${value}`).toBeNull();
			expect(await store.update("tx-1", 1, { sends: 1 }), `${field}=${value}`).toBeNull();
		}
		await first().del(key);
		await store.create(TX());
		await first().hset(key, "record", "not json");
		expect(await store.consume("tx-1", 1)).toBeNull();
	});

	it("refuses a keyPrefix that carries a brace, which would take the hash tags over", () => {
		for (const keyPrefix of ["mfat:{x}:", "mfat}:", "{mfat:"]) {
			expect(() => storeAt(keyPrefix), keyPrefix).toThrow(RangeError);
		}
	});
});

describe("createRedisMfaTransactionStore — the subject state (the MFA ADR's D21)", () => {
	/** A whole-millisecond instant near both clocks, so the deadlines below are exact. */
	const start = () => Math.floor(Date.now() / 1000) * 1000;

	it("keeps it in a hash and the weekly window in a sorted set of failure times, both under the subject's tag", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY, undefined);
		if (!reserved.ok) throw new Error("expected a reservation");
		const tag = `{${keyPart("user-1")}}`;
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[`${prefix}lock:${tag}`, `${prefix}week:${tag}`].sort(),
		);
		expect(await first().type(`${prefix}lock:${tag}`)).toBe("hash");
		expect(await first().zrange(`${prefix}week:${tag}`, 0, -1, "WITHSCORES")).toEqual([
			reserved.reservation,
			String(t),
		]);
	});

	it("gives it no TTL while a run is counted, and a deadline a day past the last thing that still counts once none is", async () => {
		// A run is kept until a success ends it (the hard limit counts it across
		// weeks); a week's failure and a trust are kept a day past the instant
		// they stop counting (MFA_CLOCK_SKEW_ALLOWANCE_MS), on the server's
		// clock — which is what Redis reclaims by.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;

		await store.noteExemptSuccess("user-1", t, POLICY, undefined);
		// A trust, nothing else: it ends trustedBrowserDays after it began.
		expect(await deadlineOf(lock)).toBe(t + 30 * DAY + DAY);

		const failed = await store.reserveSubjectAttempt("user-1", t + MINUTE, POLICY, undefined);
		if (!failed.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
		expect(await deadlineOf(lock)).toBe(-1);
		expect(await deadlineOf(week)).toBe(-1);

		const succeeded = await store.reserveSubjectAttempt(
			"user-1",
			t + 2 * MINUTE,
			POLICY,
			undefined,
		);
		if (!succeeded.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", succeeded.reservation, "success");
		// The run is over. The week counts the failure until a week after it;
		// the trust lasts until the window each reservation extended empties —
		// a week after the last one — and both keys go a day after the later.
		expect(await deadlineOf(lock)).toBe(t + 2 * MINUTE + WEEK + DAY);
		expect(await deadlineOf(week)).toBe(t + 2 * MINUTE + WEEK + DAY);

		await store.clearSubjectState("user-1");
		expect(await first().exists(lock, week)).toBe(0);
	});

	it("drops the keys once nothing in them counts", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY, undefined);
		if (!reserved.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", reserved.reservation, "void");
		expect(await first().keys(`${prefix}*`)).toEqual([]);
	});

	it("refuses to judge an attempt on a subject state it cannot read: an outage, never a pass", async () => {
		// The lock is what bounds guessing: a state read as empty would lift
		// every hold. The script refuses, and the store's caller answers 503.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		for (const [key, write] of [
			[lock, () => first().hset(lock, "r:x", "garbage")],
			[lock, () => first().hset(lock, "t:x", "1|2")],
			[week, () => first().zadd(week, "inf", "x")],
		] as const) {
			await first().del(lock, week);
			await write();
			await expect(
				store.reserveSubjectAttempt("user-1", t, POLICY, undefined),
				key,
			).rejects.toThrow(/subject state/);
			await expect(store.noteExemptSuccess("user-1", t, POLICY, undefined), key).rejects.toThrow(
				/subject state/,
			);
		}
	});
});

describe("createRedisMfaTransactionStore — the email proof at the next first binding (the MFA ADR's D25)", () => {
	it("keeps it in a key of its own with no TTL, which clearSubjectState leaves and a consume removes", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}proof:{${keyPart("user-1")}}`;
		await store.requireEmailProofAtNextBinding("user-1");
		expect(await first().pttl(key)).toBe(-1);
		await store.reserveSubjectAttempt("user-1", Date.now(), POLICY, undefined);
		await store.clearSubjectState("user-1");
		expect(await first().keys(`${prefix}*`)).toEqual([key]);
		expect(await store.consumeEmailProofRequirement("user-1")).toBe(true);
		expect(await first().exists(key)).toBe(0);
	});
});
