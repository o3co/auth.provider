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
 * contract on a real Redis, and below it: the key layout (a hash per
 * transaction expiring at its `expiresAtMs` on the server's clock; a hash per
 * subject for the lockout state beside the weekly window, a sorted set of
 * failure times; the email-proof requirement in a key with no TTL), what
 * reclaims the subject state, and the answer to a value it cannot read.
 *
 * The contract's store alternates between two connections, so its races are
 * across sockets rather than queued on one client.
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
		reserveSubjectAttempt: (subject, nowMs, policy) =>
			pick().reserveSubjectAttempt(subject, nowMs, policy),
		settleSubjectAttempt: (subject, reservation, outcome) =>
			pick().settleSubjectAttempt(subject, reservation, outcome),
		noteExemptSuccess: (subject, nowMs) => pick().noteExemptSuccess(subject, nowMs),
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
};

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => {
	const now = Date.now();
	return {
		id: "tx-1",
		purpose: "step_up",
		binding: { kind: "session", id: "express-session-1" },
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

describe("createRedisMfaTransactionStore — the transaction", () => {
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
		await store.update("tx-1", 1, { enrollment: "allowed" });
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
		expect(await ahead.update("tx-1", 1, { enrollment: "allowed" })).toBeNull();
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

	it("answers a reservation and a take on a transaction whose deadline field is missing or no finite number as absent, spending and taking nothing", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}tx:{${keyPart("tx-1")}}`;
		for (const value of [undefined, "", "soon", "inf", "-inf", "nan", "1e999"]) {
			await first().del(key);
			await store.create(TX({ challenge: CHALLENGE }));
			if (value === undefined) await first().hdel(key, "expiresAtMs");
			else await first().hset(key, "expiresAtMs", value);
			expect(await store.reserveAttempt("tx-1", 5), String(value)).toEqual({
				ok: false,
				attempts: 0,
			});
			expect(await store.takeChallenge("tx-1", 1), String(value)).toBeNull();
			expect(await first().hmget(key, "attempts", "challenge"), String(value)).toEqual([
				"0",
				JSON.stringify(CHALLENGE),
			]);
		}
	});

	it("spends an attempt on, and takes the challenge of, a login whose continuation nests deeper than cjson decodes: the scripts judge the deadline without decoding the record", async () => {
		// JSON.parse reads a thousand-and-more levels; Redis's cjson refuses
		// past a thousand. What a read answers live, the scripts must too.
		let deep: Record<string, unknown> = { leaf: true };
		for (let level = 0; level < 1100; level += 1) deep = { next: deep };
		const now = Date.now();
		const tx = TX({
			purpose: "login",
			sid: undefined,
			challenge: CHALLENGE,
			continuation: {
				primary: {
					subject: "user-1",
					user: { id: "user-1", deep },
					claims: {},
					recorded: {
						amr: ["pwd"],
						authentication: {
							primary: "pwd",
							federation: undefined,
							upstreamAmr: undefined,
							mfaAt: undefined,
						},
					},
					authTimeMs: now - 1_000,
					redirectTo: undefined,
					request: {},
				},
				done: [],
				interruptedBy: "mfa",
			},
		});
		const store = storeAt(freshPrefix());
		await store.create(tx);
		expect((await store.get("tx-1"))?.continuation?.primary.user).toStrictEqual({
			id: "user-1",
			deep,
		});
		expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: true, attempts: 1 });
		expect(await store.takeChallenge("tx-1", 1)).toStrictEqual(CHALLENGE);
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
			expect(
				await store.update("tx-1", 1, { enrollment: "allowed" }),
				`${field}=${value}`,
			).toBeNull();
		}
		await first().del(key);
		await store.create(TX());
		await first().hset(key, "record", "not json");
		expect(await store.consume("tx-1", 1)).toBeNull();
	});

	it("reads a transaction that still carries a send count or a last send, whatever they hold, and ignores both", async () => {
		// A transaction written before they left lives ten minutes at most. A
		// send count and a last send bounded mail, which is the sender's now:
		// neither holds a limit the store still keeps.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}tx:{${keyPart("tx-1")}}`;
		const tx = TX({ challenge: CHALLENGE });
		for (const [sends, lastSentAtMs] of [
			["2", "1759200000000"],
			["-1", "not json"],
			["two", '"yesterday"'],
		] as const) {
			await first().del(key);
			await store.create(tx);
			await first().hset(key, "sends", sends, "lastSentAtMs", lastSentAtMs);
			expect(await store.get("tx-1"), `${sends}, ${lastSentAtMs}`).toStrictEqual(tx);
			const updated = await store.update("tx-1", 1, { enrollment: "allowed" });
			expect(updated, `${sends}, ${lastSentAtMs}`).toStrictEqual({
				...tx,
				enrollment: "allowed",
				version: 2,
			});
			expect(await store.takeChallenge("tx-1", 2)).toStrictEqual(CHALLENGE);
			expect(await store.consume("tx-1", 2)).toStrictEqual({
				...tx,
				challenge: undefined,
				enrollment: "allowed",
				version: 2,
			});
		}
	});

	it("answers a record written before the binding, or bound by a kind it does not know, as absent: no reading of it as a session's", async () => {
		// No migration and no back-compat read: a `record` holding a
		// `sessionId`, or a binding of another kind, is unreadable, and a
		// transaction it cannot read fails closed.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}tx:{${keyPart("tx-1")}}`;
		type Fixed = Record<string, unknown> & { readonly binding: { readonly id: string } };
		const rewrites: readonly [string, (fixed: Fixed) => Record<string, unknown>][] = [
			[
				"a sessionId in place of the binding",
				({ binding, ...rest }) => ({ ...rest, sessionId: binding.id }),
			],
			[
				"a binding of a kind it does not know",
				(fixed) => ({ ...fixed, binding: { kind: "client", id: fixed.binding.id } }),
			],
		];
		for (const [what, rewrite] of rewrites) {
			await first().del(key);
			await store.create(TX());
			const fixed = JSON.parse((await first().hget(key, "record")) ?? "null") as Fixed;
			await first().hset(key, "record", JSON.stringify(rewrite(fixed)));
			expect(await store.get("tx-1"), what).toBeNull();
			expect(await store.update("tx-1", 1, { enrollment: "allowed" }), what).toBeNull();
			expect(await store.consume("tx-1", 1), what).toBeNull();
		}
	});

	it("refuses a keyPrefix that carries a brace, which would take the hash tags over", () => {
		for (const keyPrefix of ["mfat:{x}:", "mfat}:", "{mfat:"]) {
			expect(() => storeAt(keyPrefix), keyPrefix).toThrow(RangeError);
		}
	});
});

describe("createRedisMfaTransactionStore — the subject state", () => {
	/** A whole-millisecond instant near both clocks, so the deadlines below are exact. */
	const start = () => Math.floor(Date.now() / 1000) * 1000;

	it("keeps it in a hash and the weekly window in a sorted set of failure times, both under the subject's tag", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY);
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
		// weeks); a week's failure is kept a day past the instant it stops
		// counting (MFA_CLOCK_SKEW_ALLOWANCE_MS), on the server's clock — which
		// is what Redis reclaims by.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;

		// An exempt success on a subject with nothing counted keeps nothing.
		await store.noteExemptSuccess("user-1", t);
		expect(await first().exists(lock, week)).toBe(0);

		const failed = await store.reserveSubjectAttempt("user-1", t + MINUTE, POLICY);
		if (!failed.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
		expect(await deadlineOf(lock)).toBe(-1);
		expect(await deadlineOf(week)).toBe(-1);

		const succeeded = await store.reserveSubjectAttempt("user-1", t + 2 * MINUTE, POLICY);
		if (!succeeded.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", succeeded.reservation, "success");
		// The run is over. The week counts the failure until a week after it,
		// and both keys go a day after that.
		expect(await deadlineOf(lock)).toBe(t + MINUTE + WEEK + DAY);
		expect(await deadlineOf(week)).toBe(t + MINUTE + WEEK + DAY);

		await store.clearSubjectState("user-1");
		expect(await first().exists(lock, week)).toBe(0);
	});

	it("writes nothing on a refused attempt past its episode's first that forgot nothing: a held subject hammered is no write load", async () => {
		// The deadlines are set as the state changes; a refusal that changed
		// nothing leaves them where they are: no write to the AOF and every
		// replica per attempt an attacker sends at a held subject. A sentinel
		// deadline shows it.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const sentinel = t + 365 * DAY;
		const fail = async (at: number) => {
			const r = await store.reserveSubjectAttempt("user-1", at, POLICY);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		};
		// The backoff: a run is counted, so the keys carry no TTL.
		for (let i = 0; i < 5; i++) await fail(t + i);
		// The episode's first refusal records that it began; the rest write nothing.
		expect(await store.reserveSubjectAttempt("user-1", t + 9, POLICY)).toMatchObject({
			ok: false,
			first: true,
		});
		await first().pexpireat(lock, sentinel);
		await first().pexpireat(week, sentinel);
		expect(await store.reserveSubjectAttempt("user-1", t + 10, POLICY)).toMatchObject({
			ok: false,
			hold: "backoff",
			first: false,
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
			const r = await weekly.reserveSubjectAttempt("user-1", at, weekOnly);
			if (!r.ok) throw new Error("expected a reservation");
			await weekly.settleSubjectAttempt("user-1", r.reservation, "failure");
			at += MINUTE;
		}
		await weekly.noteExemptSuccess("user-1", at);
		expect(await weekly.reserveSubjectAttempt("user-1", at, weekOnly)).toMatchObject({
			ok: false,
			first: true,
		});
		expect(await deadlineOf(weeklyLock)).toBeGreaterThan(0);
		await first().pexpireat(weeklyLock, sentinel);
		await first().pexpireat(weeklyWeek, sentinel);
		expect(await weekly.reserveSubjectAttempt("user-1", at + MINUTE, weekOnly)).toMatchObject({
			ok: false,
			hold: "weekly",
			first: false,
		});
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
			const r = await store.reserveSubjectAttempt("user-1", long + i, small);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		}
		await first().pexpireat(lock, serverNow + 365 * DAY);
		expect(await store.reserveSubjectAttempt("user-1", serverNow - 5 * DAY, small)).toMatchObject({
			ok: false,
			hold: "hard",
		});
		// The week's five failures were forgotten; the run, still counted, keeps
		// the hash without a TTL.
		expect(await first().exists(week)).toBe(0);
		expect(await deadlineOf(lock)).toBe(-1);
	});

	it("drops the keys once nothing in them counts", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY);
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
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY);
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
			[week, () => first().zadd(week, "inf", "x")],
		] as const) {
			await first().del(lock, week);
			await write();
			await expect(store.reserveSubjectAttempt("user-1", t, POLICY), key).rejects.toThrow(
				/subject state/,
			);
			await expect(store.noteExemptSuccess("user-1", t), key).rejects.toThrow(/subject state/);
		}
	});

	it("ignores a trusted browser's record the lock still holds, whatever it holds: it lets no attempt through the weekly hold", async () => {
		// A trust only ever let an attempt through the weekly hold. Read as
		// nothing, the week holds every attempt, as it holds one from a
		// browser nobody trusted.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const weekOnly: MfaLockoutPolicy = { ...POLICY, threshold: 100 };
		let at = t;
		for (let i = 1; i <= 10; i++) {
			const r = await store.reserveSubjectAttempt("user-1", at, weekOnly);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
			at += MINUTE;
		}
		const until = String(t + 30 * DAY);
		await first().hset(lock, "t:digest-1", `${t}|${until}||1`, "t:digest-2", "1|2");
		expect(await store.reserveSubjectAttempt("user-1", at, weekOnly)).toEqual({
			ok: false,
			hold: "weekly",
			retryAfterMs: t + WEEK - at,
		});
		await store.noteExemptSuccess("user-1", at);
		expect(await store.reserveSubjectAttempt("user-1", at + 1, weekOnly)).toMatchObject({
			ok: false,
			hold: "weekly",
		});
		// The keys go with the week, not with the trust.
		expect(await deadlineOf(lock)).toBe(t + 9 * MINUTE + WEEK + DAY);
		expect(await deadlineOf(week)).toBe(t + 9 * MINUTE + WEEK + DAY);
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

describe("createRedisMfaTransactionStore — the same answers as core's in-process store", () => {
	// The contract samples the lockout schedule; this walks it. Each seed drives the
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
		"over a random sequence of the subject state's operations (seed %i)",
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

			for (let step = 0; step < 400; step += 1) {
				at = Math.max(start, at + choose(STEPS_MS));
				const roll = random();
				if (roll < 0.55) {
					const expected = await memory.reserveSubjectAttempt("user-1", at, SMALL);
					const actual = await redis.reserveSubjectAttempt("user-1", at, SMALL);
					const shape = (r: MfaSubjectAttemptReservation) =>
						r.ok ? "ok" : { hold: r.hold, retryAfterMs: r.retryAfterMs, first: r.first };
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
					await memory.noteExemptSuccess("user-1", at);
					await redis.noteExemptSuccess("user-1", at);
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
				const reserved = await store.reserveSubjectAttempt("user-1", t, tie);
				if (!reserved.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
			}
			answers.push(await store.reserveSubjectAttempt("user-1", t + 1, tie));
		}
		expect(answers[1]).toEqual(answers[0]);
		expect(answers[0]).toEqual({ ok: false, hold: "weekly", retryAfterMs: WEEK - 1, first: true });
	});

	it("ends an attempt reserved at the very instant of an exempt success, as core's store does", async () => {
		// "Up to its time" includes the instant itself: threshold - 1 failures
		// before it and one at it are all ended, so four more failures after it
		// are still short of a lock.
		const t = Math.floor(Date.now() / 1000) * 1000;
		const answers: boolean[] = [];
		for (const store of [createMemoryMfaTransactionStore(), storeAt(freshPrefix())]) {
			for (let i = 0; i < 4; i++) {
				const reserved = await store.reserveSubjectAttempt("user-1", t + 10 * i, POLICY);
				if (!reserved.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
			}
			await store.noteExemptSuccess("user-1", t + 30);
			for (let i = 0; i < 4; i++) {
				const next = await store.reserveSubjectAttempt("user-1", t + 40 + i, POLICY);
				if (!next.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", next.reservation, "failure");
			}
			answers.push((await store.reserveSubjectAttempt("user-1", t + 50, POLICY)).ok);
		}
		expect(answers).toEqual([true, true]);
	});
});

describe("createRedisMfaTransactionStore — the email proof at the next first binding", () => {
	it("keeps it in a key of its own with no TTL, which clearSubjectState leaves and a consume removes", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}proof:{${keyPart("user-1")}}`;
		await store.requireEmailProofAtNextBinding("user-1");
		expect(await first().pttl(key)).toBe(-1);
		await store.reserveSubjectAttempt("user-1", Date.now(), POLICY);
		await store.clearSubjectState("user-1");
		expect(await first().keys(`${prefix}*`)).toEqual([key]);
		expect(await store.consumeEmailProofRequirement("user-1")).toBe(true);
		expect(await first().exists(key)).toBe(0);
	});
});
