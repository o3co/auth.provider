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

import {
	createMemoryMfaTransactionStore,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptReservation,
	type MfaTransaction,
	type MfaTransactionStore,
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

/** A challenge a verification takes, as core's contract suite has one. */
const CHALLENGE = {
	factorId: "factor-1",
	kind: "webauthn",
	state: "sealed-challenge-state",
	expiresAtMs: Date.now() + 10 * MINUTE,
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

	it("answers a transaction past its expiresAtMs on its own clock as absent, though the server still holds it", async () => {
		// A server whose clock runs behind keeps the key past the deadline; the
		// store's own clock (`now`, the host's by default) is the transaction's
		// too, so get, update and consume cannot complete a ceremony past it.
		const prefix = freshPrefix();
		const onTime = storeAt(prefix);
		const ahead = createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(first()),
			keyPrefix: prefix,
			now: () => Date.now() + 11 * MINUTE,
		});
		const tx = TX();
		await onTime.create(tx);
		expect(await ahead.get("tx-1")).toBeNull();
		expect(await ahead.update("tx-1", 1, { sends: 1 })).toBeNull();
		expect(await onTime.get("tx-1")).toStrictEqual(tx);
		expect(await ahead.consume("tx-1", 1)).toBeNull();
		// …and it refuses to create one whose expiry is already past on that clock.
		await expect(ahead.create(TX({ id: "tx-2" }))).rejects.toThrow(RangeError);
	});

	it("answers a reservation and a take on a transaction past its expiresAtMs on its own clock as absent too, spending and taking nothing, though the server still holds it", async () => {
		// Each is one script, so the store's clock has to reach the script: a
		// server whose clock runs behind would otherwise spend an attempt on,
		// and hand out the challenge of, a transaction every read calls gone.
		const prefix = freshPrefix();
		const onTime = storeAt(prefix);
		const ahead = createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(first()),
			keyPrefix: prefix,
			now: () => Date.now() + 11 * MINUTE,
		});
		await onTime.create(TX({ challenge: CHALLENGE }));
		expect(await ahead.reserveAttempt("tx-1", 5)).toEqual({ ok: false, attempts: 0 });
		expect(await ahead.takeChallenge("tx-1", 1)).toBeNull();
		expect(await onTime.get("tx-1")).toMatchObject({ attempts: 0, challenge: CHALLENGE });
	});

	it("judges the deadline of a reservation and a take as a read does, to the fraction of a millisecond: at expiresAtMs it is gone, a moment before it is not", async () => {
		const prefix = freshPrefix();
		const expiresAtMs = Date.now() + 10 * MINUTE + 0.25;
		await storeAt(prefix).create(TX({ expiresAtMs, challenge: CHALLENGE }));
		const at = (nowMs: number): MfaTransactionStore =>
			createRedisMfaTransactionStore({
				client: makeIoredisMfaTransactionStoreClient(first()),
				keyPrefix: prefix,
				now: () => nowMs,
			});
		expect(await at(expiresAtMs).get("tx-1")).toBeNull();
		expect(await at(expiresAtMs).reserveAttempt("tx-1", 5)).toEqual({ ok: false, attempts: 0 });
		expect(await at(expiresAtMs).takeChallenge("tx-1", 1)).toBeNull();
		const before = at(expiresAtMs - 0.125);
		expect(await before.reserveAttempt("tx-1", 5)).toEqual({ ok: true, attempts: 1 });
		expect(await before.takeChallenge("tx-1", 1)).toStrictEqual(CHALLENGE);
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
		expect(await first().zrange(`${prefix}week:${tag}`, "0", "-1", "WITHSCORES")).toEqual([
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

	it("writes nothing on a refused attempt that forgot nothing: a held subject hammered is no write load", async () => {
		// Each refusal used to re-set both keys' deadlines — a write to the AOF
		// and every replica per attempt an attacker sends at a held subject.
		// The deadlines are set as the state changes; a refusal that changed
		// nothing leaves them where they are. A sentinel deadline shows it.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const sentinel = t + 365 * DAY;
		const fail = async (at: number) => {
			const r = await store.reserveSubjectAttempt("user-1", at, POLICY, undefined);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		};
		// The backoff: a run is counted, so the keys carry no TTL.
		for (let i = 0; i < 5; i++) await fail(t + i);
		await first().pexpireat(lock, sentinel);
		await first().pexpireat(week, sentinel);
		expect(await store.reserveSubjectAttempt("user-1", t + 10, POLICY, undefined)).toMatchObject({
			ok: false,
			hold: "backoff",
		});
		expect(await deadlineOf(lock)).toBe(sentinel);
		expect(await deadlineOf(week)).toBe(sentinel);
		// The weekly hold, with the run ended: the keys carry a deadline.
		const weeklyPrefix = freshPrefix();
		const weekly = storeAt(weeklyPrefix);
		const weeklyLock = `${weeklyPrefix}lock:{${keyPart("user-1")}}`;
		const weeklyWeek = `${weeklyPrefix}week:{${keyPart("user-1")}}`;
		// No backoff before the hard limit, so ten failures in a row fill the week.
		const weekOnly: MfaLockoutPolicy = { ...POLICY, threshold: 100 };
		let at = t;
		for (let i = 1; i <= 10; i++) {
			const r = await weekly.reserveSubjectAttempt("user-1", at, weekOnly, undefined);
			if (!r.ok) throw new Error("expected a reservation");
			await weekly.settleSubjectAttempt("user-1", r.reservation, "failure");
			at += MINUTE;
		}
		await weekly.noteExemptSuccess("user-1", at, weekOnly, undefined);
		expect(await deadlineOf(weeklyLock)).toBeGreaterThan(0);
		await first().pexpireat(weeklyLock, sentinel);
		await first().pexpireat(weeklyWeek, sentinel);
		expect(
			await weekly.reserveSubjectAttempt("user-1", at + MINUTE, weekOnly, undefined),
		).toMatchObject({ ok: false, hold: "weekly" });
		expect(await deadlineOf(weeklyLock)).toBe(sentinel);
		expect(await deadlineOf(weeklyWeek)).toBe(sentinel);
	});

	it("sets the deadlines again on a refused attempt that forgot something", async () => {
		// A caller far behind the server forgets what stopped counting a day
		// before its own time; the keys' deadlines follow what is left.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const serverNow = await serverClock(first)();
		const small: MfaLockoutPolicy = { ...POLICY, threshold: 5, hardLimit: 5 };
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const long = serverNow - 20 * DAY;
		for (let i = 0; i < 5; i++) {
			const r = await store.reserveSubjectAttempt("user-1", long + i, small, undefined);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		}
		await first().pexpireat(lock, serverNow + 365 * DAY);
		expect(
			await store.reserveSubjectAttempt("user-1", serverNow - 5 * DAY, small, undefined),
		).toMatchObject({ ok: false, hold: "hard" });
		// The week's five failures were forgotten; the run, still counted, keeps
		// the hash without a TTL.
		expect(await first().exists(week)).toBe(0);
		expect(await deadlineOf(lock)).toBe(-1);
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

	it("settles nothing on a subject state it cannot read: the refusal comes before any write", async () => {
		// Lua's isolation is not a transaction: a script that wrote and then
		// failed on a corrupt field would leave the reservation half-settled.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY, undefined);
		if (!reserved.ok) throw new Error("expected a reservation");
		await first().hset(lock, "r:x", "garbage");
		for (const outcome of ["success", "void", "failure"] as const) {
			await expect(
				store.settleSubjectAttempt("user-1", reserved.reservation, outcome),
				outcome,
			).rejects.toThrow(/subject state/);
			expect(await first().hget(lock, `p:${reserved.reservation}`), outcome).not.toBeNull();
			expect(await first().hget(lock, `r:${reserved.reservation}`), outcome).not.toBeNull();
			expect(await first().zscore(week, reserved.reservation), outcome).toBe(String(t));
		}
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

/** A small seeded generator (mulberry32): the same sequence for a seed on every run. */
const seeded = (seed: number): (() => number) => {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
	};
};

describe("createRedisMfaTransactionStore — the same answers as core's in-process store (the MFA ADR's D21)", () => {
	// The contract samples D21's schedule; this walks it. Each seed drives the
	// same random sequence of reservations, settlements, exempt successes and
	// clears through core's in-process store and this one, and every answer
	// must agree — a hold, its kind and its retry to the millisecond. A small
	// policy reaches every hold within a few hundred steps. Callers' clocks
	// disagree: time steps back as well as forward, and often not at all, so
	// two events share an instant — but never to before the walk began, ahead
	// of both stores' clocks, so neither forgets anything the other still
	// counts.
	const SMALL: MfaLockoutPolicy = {
		threshold: 3,
		baseSeconds: 60,
		maxSeconds: 600,
		memorySeconds: 3_600,
		weeklyBudget: 6,
		hardLimit: 12,
		trustedBrowsers: 2,
		trustedBrowserDays: 3,
	};
	const STEPS_MS = [
		0,
		0,
		0,
		1,
		-1,
		999,
		-999,
		MINUTE,
		-MINUTE,
		10 * MINUTE,
		-10 * MINUTE,
		60 * MINUTE,
		DAY,
		3 * DAY,
	];
	const OUTCOMES = ["failure", "failure", "success", "void"] as const;

	it.each(Array.from({ length: 16 }, (_, i) => i + 1))(
		"over a random sequence of D21's operations (seed %i)",
		async (seed) => {
			const random = seeded(seed);
			const choose = <T,>(list: readonly T[]): T => list[Math.floor(random() * list.length)] as T;
			const memory = createMemoryMfaTransactionStore();
			const redis = storeAt(freshPrefix());
			const serverNow = await serverClock(first)();
			const start = Math.ceil(Math.max(Date.now(), serverNow) / 1000) * 1000 + 1000;
			let at = start;
			/** Each reservation in flight, as each store named it. */
			const pending: Array<readonly [string, string]> = [];
			/** Each browser an exempt success trusted, as each store named it. */
			const browsers: Array<readonly [string, string]> = [];
			const browserPair = (): readonly [string | undefined, string | undefined] => {
				const roll = random();
				if (roll < 0.4 || browsers.length === 0) return [undefined, undefined];
				if (roll < 0.5) return ["not-a-browser", "not-a-browser"];
				return choose(browsers);
			};

			for (let step = 0; step < 400; step += 1) {
				at = Math.max(start, at + choose(STEPS_MS));
				const roll = random();
				if (roll < 0.55) {
					const [mine, theirs] = browserPair();
					const expected = await memory.reserveSubjectAttempt("user-1", at, SMALL, mine);
					const actual = await redis.reserveSubjectAttempt("user-1", at, SMALL, theirs);
					const shape = (r: MfaSubjectAttemptReservation) =>
						r.ok ? "ok" : { hold: r.hold, retryAfterMs: r.retryAfterMs };
					expect(shape(actual), `step ${step}`).toEqual(shape(expected));
					if (expected.ok && actual.ok) pending.push([expected.reservation, actual.reservation]);
				} else if (roll < 0.85 && pending.length > 0) {
					const [mine, theirs] = pending.splice(Math.floor(random() * pending.length), 1)[0] as [
						string,
						string,
					];
					const outcome = choose(OUTCOMES);
					await memory.settleSubjectAttempt("user-1", mine, outcome);
					await redis.settleSubjectAttempt("user-1", theirs, outcome);
				} else if (roll < 0.97) {
					const [mine, theirs] = browserPair();
					const expected = await memory.noteExemptSuccess("user-1", at, SMALL, mine);
					const actual = await redis.noteExemptSuccess("user-1", at, SMALL, theirs);
					browsers.push([expected.browser, actual.browser]);
				} else {
					await memory.clearSubjectState("user-1");
					await redis.clearSubjectState("user-1");
					pending.length = 0;
				}
			}
		},
	);

	it("reports the weekly hold when it ends at the same instant as the backoff, as core's store does", async () => {
		// weeklyBudget failures at one instant, under a backoff as long as the
		// week: both holds end a week later. The port reports the weekly one.
		const tie: MfaLockoutPolicy = {
			...POLICY,
			threshold: 3,
			baseSeconds: 7 * 86_400,
			maxSeconds: 7 * 86_400,
			weeklyBudget: 3,
		};
		const t = Math.floor(Date.now() / 1000) * 1000;
		const answers: MfaSubjectAttemptReservation[] = [];
		for (const store of [createMemoryMfaTransactionStore(), storeAt(freshPrefix())]) {
			for (let i = 0; i < 3; i++) {
				const reserved = await store.reserveSubjectAttempt("user-1", t, tie, undefined);
				if (!reserved.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
			}
			answers.push(await store.reserveSubjectAttempt("user-1", t + 1, tie, undefined));
		}
		expect(answers[1]).toEqual(answers[0]);
		expect(answers[0]).toEqual({ ok: false, hold: "weekly", retryAfterMs: WEEK - 1 });
	});

	it("ends an attempt reserved at the very instant of an exempt success, as core's store does", async () => {
		// "Up to its time" includes the instant itself: threshold - 1 failures
		// before it and one at it are all ended, so four more failures after it
		// are still short of a lock.
		const t = Math.floor(Date.now() / 1000) * 1000;
		const answers: boolean[] = [];
		for (const store of [createMemoryMfaTransactionStore(), storeAt(freshPrefix())]) {
			for (let i = 0; i < 4; i++) {
				const reserved = await store.reserveSubjectAttempt("user-1", t + 10 * i, POLICY, undefined);
				if (!reserved.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
			}
			await store.noteExemptSuccess("user-1", t + 30, POLICY, undefined);
			for (let i = 0; i < 4; i++) {
				const next = await store.reserveSubjectAttempt("user-1", t + 40 + i, POLICY, undefined);
				if (!next.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", next.reservation, "failure");
			}
			answers.push((await store.reserveSubjectAttempt("user-1", t + 50, POLICY, undefined)).ok);
		}
		expect(answers).toEqual([true, true]);
	});

	it("keeps a trust's window where a later attempt set it when a caller behind extends it, as core's store does", async () => {
		// An attempt reserved by a caller ahead sets the window of the trust an
		// exempt success grants; one reserved afterwards by a caller behind
		// must not pull that window back.
		const t = Math.floor(Date.now() / 1000) * 1000;
		const answers: MfaSubjectAttemptReservation[] = [];
		for (const store of [createMemoryMfaTransactionStore(), storeAt(freshPrefix())]) {
			const ahead = await store.reserveSubjectAttempt("user-1", t + DAY, POLICY, undefined);
			if (!ahead.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", ahead.reservation, "failure");
			const { browser } = await store.noteExemptSuccess("user-1", t, POLICY, undefined);
			const behind = await store.reserveSubjectAttempt("user-1", t + 1, POLICY, browser);
			if (!behind.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", behind.reservation, "success");
			// Fill the week once the behind caller's window would have emptied and
			// before the ahead caller's does: only a window kept where the ahead
			// attempt set it still trusts the browser there.
			const from = t + 1 + WEEK + MINUTE;
			for (let i = 0; i < 12; i++) {
				const r = await store.reserveSubjectAttempt("user-1", from + i, POLICY, undefined);
				if (!r.ok) break;
				await store.settleSubjectAttempt(
					"user-1",
					r.reservation,
					i % 4 === 3 ? "success" : "failure",
				);
			}
			answers.push(await store.reserveSubjectAttempt("user-1", from + 20, POLICY, browser));
		}
		expect(answers.map((answer) => answer.ok)).toEqual([true, true]);
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
