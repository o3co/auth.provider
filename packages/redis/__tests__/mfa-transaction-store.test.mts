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
 * failure times; the email-proof requirement in a key with no TTL; a
 * session's proof and a subject's first-binding mark in strings expiring at
 * their ends), what reclaims the subject state, and the answer to a value it
 * cannot read.
 *
 * The contract's store alternates between two connections, so its races are
 * across sockets rather than queued on one client.
 */

import { createHash } from "node:crypto";
import {
	createMemoryMfaTransactionStore,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	MFA_MAX_TRANSACTIONS_PER_BINDING,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptReservation,
	type MfaSubjectRecoveryAnswer,
	type MfaSubjectRecoveryApplication,
	type MfaTransaction,
	type MfaTransactionStore,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { MfaTransactionStoreClient } from "#/clients.mjs";
import {
	MFA_FIRST_BINDING_NOTE,
	MFA_FIRST_BINDING_READ,
	MFA_RECOVERY_SET_FLOOR_RAISE,
	MFA_SUBJECT_EXEMPT,
	MFA_SUBJECT_LEASE_RELEASE,
	MFA_SUBJECT_RECOVERY_APPLY,
} from "#/ioredis/scripts/mfa.mjs";
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

/**
 * Mark values carrying a field a note never writes: nested deeper than the
 * scripts' JSON reader decodes, and holding a lone surrogate.
 */
const odd = (atMs: number): string[] => {
	const head = `{"atMs":${atMs},"untilMs":${atMs + 10 * 60_000},"x":`;
	return [`${head}${"[".repeat(1_200)}${"]".repeat(1_200)}}`, `${head}"\\ud800"}`];
};

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
		noteExemptSuccess: (subject, nowMs, policy) => pick().noteExemptSuccess(subject, nowMs, policy),
		requireEmailProofAtNextBinding: (subject) => pick().requireEmailProofAtNextBinding(subject),
		emailProofRequiredAtNextBinding: (subject) => pick().emailProofRequiredAtNextBinding(subject),
		consumeEmailProofRequirement: (subject) => pick().consumeEmailProofRequirement(subject),
		recordSessionEmailProof: (subject, sid, provedAtMs, untilMs) =>
			pick().recordSessionEmailProof(subject, sid, provedAtMs, untilMs),
		sessionEmailProofAt: (subject, sid, nowMs) => pick().sessionEmailProofAt(subject, sid, nowMs),
		noteFirstBinding: (subject, atMs, untilMs) => pick().noteFirstBinding(subject, atMs, untilMs),
		firstBindingAt: (subject, nowMs) => pick().firstBindingAt(subject, nowMs),
		subjectGeneration: (subject) => pick().subjectGeneration(subject),
		acquireSubjectLease: (subject, request) => pick().acquireSubjectLease(subject, request),
		releaseSubjectLease: (subject, token) => pick().releaseSubjectLease(subject, token),
		authorizeSubjectRecovery: (subject, authorization) =>
			pick().authorizeSubjectRecovery(subject, authorization),
		applySubjectRecovery: (subject, application) =>
			pick().applySubjectRecovery(subject, application),
		raiseRecoverySetFloor: (subject, raise) => pick().raiseRecoverySetFloor(subject, raise),
		recoverySetFloor: (subject) => pick().recoverySetFloor(subject),
	};
};

runMfaTransactionStoreContract(async () => alternating(freshPrefix()), {
	expiry: { now: serverClock(first), passed: serverPasses(first) },
});

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
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

let resets = 0;

/** Applies `operation` for `subject` under a lease of its own, authorized first: the answer. */
async function applied(
	store: MfaTransactionStore,
	subject: string,
	application: Partial<MfaSubjectRecoveryApplication> = {},
): Promise<MfaSubjectRecoveryAnswer> {
	resets += 1;
	const operation = application.operation ?? "reset";
	const sid = operation === "reset" ? undefined : "sid-1";
	const lease = await store.acquireSubjectLease(subject, {
		ttlMs: 60_000,
		generation: await store.subjectGeneration(subject),
	});
	if (lease.outcome !== "acquired") throw new Error(`expected a lease: ${lease.outcome}`);
	try {
		await store.authorizeSubjectRecovery(subject, {
			operation,
			sid,
			recoveryId: `recovery-${resets}`,
			expiresAtMs: Date.now() + 10 * MINUTE,
		});
		return await store.applySubjectRecovery(subject, {
			operation,
			sid,
			nowMs: Date.now(),
			leaseToken: lease.token,
			sessionsBoundaryMs: undefined,
			guessableBoundSinceMs: operation === "reset" ? undefined : null,
			...application,
		});
	} finally {
		await store.releaseSubjectLease(subject, lease.token);
	}
}

/** The operator reset of `subject`: its lock state ends whole. */
async function resetSubject(store: MfaTransactionStore, subject: string): Promise<void> {
	const answer = await applied(store, subject);
	if (answer.outcome !== "applied")
		throw new Error(`expected the reset applied: ${answer.outcome}`);
}

/** The absolute deadline of `key` on the server's clock, in epoch ms; -1 for none, -2 for no key. */
const deadlineOf = async (key: string): Promise<number> =>
	Number(await first().call("PEXPIRETIME", key));

/** A binding's index, as the adapter names it: the SHA-256 of the whole binding, never its id. */
const bindingKey = (prefix: string, binding: { readonly kind: string; readonly id: string }) =>
	`${prefix}binding:{${createHash("sha256")
		.update(JSON.stringify([binding.kind, binding.id]))
		.digest("base64url")}}`;

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
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[key, bindingKey(prefix, TX().binding)].sort(),
		);
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

describe("createRedisMfaTransactionStore — the live transactions one binding holds", () => {
	const N = MFA_MAX_TRANSACTIONS_PER_BINDING;
	const A = { kind: "session", id: "Qx7-dP_2mZkL9vRt3YbN8cW-4sHj_E1a" } as const;
	const B = { kind: "session", id: "Rk2_aW-9pLmX3vQt7ZbN0cY-5sJh_F8b" } as const;

	/** `count` transactions `<prefix>-<i>` bound to `binding`, each expiring a second after the one before: their `expiresAtMs`. */
	async function opened(
		store: MfaTransactionStore,
		prefix: string,
		count: number,
		binding: MfaTransaction["binding"],
	): Promise<number[]> {
		const base = Date.now() + 10 * MINUTE;
		const expiries: number[] = [];
		for (let i = 0; i < count; i++) {
			const expiresAtMs = base + i * 1_000 + 0.25;
			await store.create(TX({ id: `${prefix}-${i}`, binding, expiresAtMs }));
			expiries.push(expiresAtMs);
		}
		return expiries;
	}

	it("indexes a binding's transactions in one sorted set, <prefix>binding:{<digest>}, scored by expiresAtMs and expiring at the latest, rounded up", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const expiries = await opened(store, "tab", 2, A);
		const index = bindingKey(prefix, A);
		expect(await first().type(index)).toBe("zset");
		const members = await first().zrange(index, "0", "-1", "WITHSCORES");
		expect(members).toHaveLength(4);
		expect([Number(members[1]), Number(members[3])]).toEqual(expiries);
		expect(await deadlineOf(index)).toBe(Math.ceil(expiries[1] as number));
		// Each member names its transaction's key part, after the incarnation `create` wrote.
		for (const [i, member] of [members[0], members[2]].entries()) {
			const incarnation = await first().hget(`${prefix}tx:{${keyPart(`tab-${i}`)}}`, "incarnation");
			expect(member).toBe(`${incarnation}:${keyPart(`tab-${i}`)}`);
		}
	});

	it("keeps the express session id out of every key it writes", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await opened(store, "tab", N + 1, A);
		await store.consume("tab-3", 1);
		for (const key of await first().keys(`${prefix}*`)) {
			expect(key).not.toContain(A.id);
			expect(key).not.toContain(keyPart(A.id));
		}
	});

	it("holds at most N members, its deadline the latest of theirs, and ends an evicted transaction's key", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const expiries = await opened(store, "tab", N + 2, A);
		const index = bindingKey(prefix, A);
		expect(await first().zcard(index)).toBe(N);
		expect(await deadlineOf(index)).toBe(Math.ceil(expiries[N + 1] as number));
		expect(await first().exists(`${prefix}tx:{${keyPart("tab-0")}}`)).toBe(0);
		expect(await first().exists(`${prefix}tx:{${keyPart("tab-1")}}`)).toBe(0);
	});

	it("takes a transaction out of the index when it is consumed or its attempts end, and the key goes with the last", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await opened(store, "tab", 2, A);
		const index = bindingKey(prefix, A);
		await store.consume("tab-0", 1);
		expect(await first().zcard(index)).toBe(1);
		await store.reserveAttempt("tab-1", 1);
		await store.reserveAttempt("tab-1", 1);
		expect(await first().exists(index)).toBe(0);
	});

	it("brings the index's deadline back to the latest left when the latest-expiring transaction leaves", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const expiries = await opened(store, "tab", 3, A);
		const index = bindingKey(prefix, A);
		await store.consume("tab-2", 1);
		expect(await deadlineOf(index)).toBe(Math.ceil(expiries[1] as number));
		await store.reserveAttempt("tab-1", 1);
		await store.reserveAttempt("tab-1", 1);
		expect(await deadlineOf(index)).toBe(Math.ceil(expiries[0] as number));
	});

	it("never ends another binding's transaction: an eviction deletes a key only while it holds the incarnation the index took", async () => {
		// A member left behind (its transaction removed without it), and the
		// id taken again by another binding: evicting the member must leave
		// the other binding's transaction alone.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await store.create(TX({ id: "shared", binding: A, expiresAtMs: Date.now() + 5 * MINUTE }));
		await first().del(`${prefix}tx:{${keyPart("shared")}}`);
		await store.create(TX({ id: "shared", binding: B }));
		await opened(store, "tab", N, A);
		expect(await first().zcard(bindingKey(prefix, A))).toBe(N);
		expect(await store.get("shared")).toMatchObject({ binding: B });
		expect(await first().zcard(bindingKey(prefix, B))).toBe(1);
	});

	it("refuses a create whose binding index it cannot write: an outage", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await first().set(bindingKey(prefix, A), "not a sorted set");
		await expect(store.create(TX({ binding: A }))).rejects.toThrow();
		// Refused after the write: the transaction it wrote stands until it expires.
		expect(await first().exists(`${prefix}tx:{${keyPart("tx-1")}}`)).toBe(1);
	});

	/** A store over a client whose `fail` operations reject, and the warnings it logs. */
	function failing(prefix: string, fail: Partial<Record<keyof MfaTransactionStoreClient, true>>) {
		const real = makeIoredisMfaTransactionStoreClient(first());
		const down = async (): Promise<never> => {
			throw new Error("connection lost");
		};
		const client: MfaTransactionStoreClient = {
			...real,
			...(fail.evictTransaction ? { evictTransaction: down } : {}),
			...(fail.unindexTransaction ? { unindexTransaction: down } : {}),
		};
		const warned: [Record<string, unknown>, string][] = [];
		const store = createRedisMfaTransactionStore({
			client,
			keyPrefix: prefix,
			logger: { warn: (obj, msg) => warned.push([obj, msg]) },
		});
		return { store, warned };
	}

	it("keeps a create whose eviction fails: the new transaction stands, the one not ended stays until it expires, and it warns", async () => {
		const prefix = freshPrefix();
		const { store, warned } = failing(prefix, { evictTransaction: true });
		await opened(store, "tab", N + 1, A);
		expect(await store.get(`tab-${N}`)).not.toBeNull();
		expect(await store.get("tab-0")).not.toBeNull();
		expect(warned.map(([, msg]) => msg)).toEqual(["mfa_transaction_evict_failed"]);
		expect(warned[0]?.[0]).toMatchObject({ err: expect.anything() });
	});

	it("answers a consume and a reservation past max as usual when the member cannot be taken out, and warns", async () => {
		const prefix = freshPrefix();
		const { store, warned } = failing(prefix, { unindexTransaction: true });
		await opened(store, "tab", 2, A);
		expect(await store.consume("tab-0", 1)).not.toBeNull();
		expect(await store.reserveAttempt("tab-1", 1)).toEqual({ ok: true, attempts: 1 });
		expect(await store.reserveAttempt("tab-1", 1)).toEqual({ ok: false, attempts: 1 });
		expect(warned.map(([obj, msg]) => [msg, obj.operation])).toEqual([
			["mfa_transaction_unindex_failed", "consume"],
			["mfa_transaction_unindex_failed", "reserveAttempt"],
		]);
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
		await store.noteExemptSuccess("user-1", t, POLICY);
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

		await resetSubject(store, "user-1");
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
		await weekly.noteExemptSuccess("user-1", at, weekOnly);
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

	it("keeps the hard hold, and no TTL, through an exempt success, the script loaded again after the cache was flushed", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const small: MfaLockoutPolicy = { ...POLICY, threshold: 5, hardLimit: 5 };
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		for (let i = 0; i < 5; i++) {
			const r = await store.reserveSubjectAttempt("user-1", t + i, small);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		}
		await store.noteExemptSuccess("user-1", t + 5, small);
		await first().script("FLUSH");
		await store.noteExemptSuccess("user-1", t + 6, small);
		expect(await first().script("EXISTS", MFA_SUBJECT_EXEMPT.sha)).toEqual([1]);
		expect(await store.reserveSubjectAttempt("user-1", t + 7, small)).toMatchObject({
			ok: false,
			hold: "hard",
			retryAfterMs: null,
		});
		expect(await deadlineOf(lock)).toBe(-1);
	});

	it("keeps the hard hold in the lock hash's hard field, the later of the time it was fixed and its run's newest attempt, and the keys with no TTL after the run has ended", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const two: MfaLockoutPolicy = { ...POLICY, threshold: 2, hardLimit: 2 };
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const failed = await store.reserveSubjectAttempt("user-1", t, two);
		if (!failed.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
		const second = await store.reserveSubjectAttempt("user-1", t + MINUTE, two);
		if (!second.ok) throw new Error("expected a reservation");
		expect(await first().hget(lock, "hard")).toBe(String(t + MINUTE));
		await store.settleSubjectAttempt("user-1", second.reservation, "success");
		expect(await deadlineOf(lock)).toBe(-1);
		expect(await deadlineOf(week)).toBe(-1);
		expect(await store.reserveSubjectAttempt("user-1", t + 2 * MINUTE, two)).toMatchObject({
			ok: false,
			hold: "hard",
			retryAfterMs: null,
		});
	});

	it("records as the hard hold's time the run's newest attempt when the call that fixes it is dated before it, at a reservation and at an exempt success", async () => {
		const lower: MfaLockoutPolicy = {
			...POLICY,
			threshold: 2,
			baseSeconds: 60,
			maxSeconds: 60,
			hardLimit: 5,
		};
		const six: MfaLockoutPolicy = { ...lower, hardLimit: 6 };
		for (const fixes of ["reservation", "exempt success"] as const) {
			const prefix = freshPrefix();
			const store = storeAt(prefix);
			const lock = `${prefix}lock:{${keyPart("user-1")}}`;
			let at = start();
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				const r = await store.reserveSubjectAttempt("user-1", at, six);
				if (!r.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", r.reservation, "failure");
			}
			if (fixes === "reservation") {
				expect(await store.reserveSubjectAttempt("user-1", at - HOUR, lower), fixes).toMatchObject({
					ok: false,
					hold: "hard",
				});
			} else {
				await store.noteExemptSuccess("user-1", at - HOUR, lower);
			}
			expect(await first().hget(lock, "hard"), fixes).toBe(String(at));
		}
	});

	it("fixes the hard hold on a run at the limit written with no hard field, at a reservation or an exempt success dated before its last failure", async () => {
		const six: MfaLockoutPolicy = {
			...POLICY,
			threshold: 2,
			baseSeconds: 60,
			maxSeconds: 60,
			hardLimit: 6,
		};
		const seven: MfaLockoutPolicy = { ...six, hardLimit: 7 };
		for (const finds of ["reservation", "exempt success"] as const) {
			const prefix = freshPrefix();
			const store = storeAt(prefix);
			const lock = `${prefix}lock:{${keyPart("user-1")}}`;
			let at = start();
			for (let i = 0; i < 6; i++) {
				at += MINUTE;
				const r = await store.reserveSubjectAttempt("user-1", at, six);
				if (!r.ok) throw new Error("expected a reservation");
				await store.settleSubjectAttempt("user-1", r.reservation, "failure");
			}
			// As a release that kept no hard field left it.
			await first().hdel(lock, "hard");
			// Fixed at the later of the call's time and the last failure's.
			if (finds === "reservation") {
				expect(await store.reserveSubjectAttempt("user-1", at + DAY, six), finds).toMatchObject({
					hold: "hard",
				});
				expect(await first().hget(lock, "hard"), finds).toBe(String(at + DAY));
			} else {
				await store.noteExemptSuccess("user-1", at - 1, six);
				expect(await first().hget(lock, "hard"), finds).toBe(String(at));
			}
			expect(await store.reserveSubjectAttempt("user-1", at + 2 * DAY, seven), finds).toMatchObject(
				{
					hold: "hard",
				},
			);
		}
	});

	it("takes off, at a refusal, a TTL a held hash was given: a deadline another release set does not end the hold", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const two: MfaLockoutPolicy = { ...POLICY, threshold: 2, hardLimit: 2 };
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		for (let i = 0; i < 2; i++) {
			const r = await store.reserveSubjectAttempt("user-1", t + i, two);
			if (!r.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		}
		// The episode's first refusal is behind it: the next writes no mark.
		expect(await store.reserveSubjectAttempt("user-1", t + 2, two)).toMatchObject({ first: true });
		await first().pexpire(lock, 10 * MINUTE);
		await first().pexpire(week, 10 * MINUTE);
		expect(await store.reserveSubjectAttempt("user-1", t + 3, two)).toMatchObject({
			hold: "hard",
			first: false,
		});
		expect(await deadlineOf(lock)).toBe(-1);
		expect(await deadlineOf(week)).toBe(-1);
	});

	it("refuses every lock operation on a hard field it cannot read: an outage, never a pass, and nothing settled", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const reserved = await store.reserveSubjectAttempt("user-1", t, POLICY);
		if (!reserved.ok) throw new Error("expected a reservation");
		for (const garbage of ["garbage", "inf", ""]) {
			await first().hset(lock, "hard", garbage);
			await expect(store.reserveSubjectAttempt("user-1", t + 1, POLICY), garbage).rejects.toThrow(
				/subject state/,
			);
			await expect(store.noteExemptSuccess("user-1", t + 1, POLICY), garbage).rejects.toThrow(
				/subject state/,
			);
			await expect(
				store.settleSubjectAttempt("user-1", reserved.reservation, "success"),
				garbage,
			).rejects.toThrow(/subject state/);
			expect(await first().hget(lock, `p:${reserved.reservation}`), garbage).not.toBeNull();
		}
	});

	it("refuses an exempt success whose hardLimit argument is missing or not a number, naming the argument, and writes nothing", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const t = start();
		const lock = `${prefix}lock:{${keyPart("user-1")}}`;
		const week = `${prefix}week:{${keyPart("user-1")}}`;
		const r = await store.reserveSubjectAttempt("user-1", t, POLICY);
		if (!r.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", r.reservation, "failure");
		const before = await first().hgetall(lock);
		for (const args of [[String(t + 1)], [String(t + 1), "abc"], [String(t + 1), "inf"]]) {
			await expect(
				first().eval(MFA_SUBJECT_EXEMPT.source, 2, lock, week, ...args),
				JSON.stringify(args),
			).rejects.toThrow("MFA subject state: the hardLimit argument is missing or not a number");
			expect(await first().hgetall(lock), JSON.stringify(args)).toEqual(before);
		}
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
			await expect(store.noteExemptSuccess("user-1", t, POLICY), key).rejects.toThrow(
				/subject state/,
			);
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
			first: true,
		});
		await store.noteExemptSuccess("user-1", at, weekOnly);
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
					await memory.noteExemptSuccess("user-1", at, SMALL);
					await redis.noteExemptSuccess("user-1", at, SMALL);
				} else if (roll < 0.985) {
					// A recover at this step's time, a boundary somewhere before it or none,
					// and a rebind before or after the hard hold, or none.
					const recover = {
						operation: "recover" as const,
						nowMs: at,
						sessionsBoundaryMs: choose([undefined, at - choose(STEPS_MS.filter((s) => s >= 0))]),
						guessableBoundSinceMs: choose([null, at - DAY, at + DAY]),
					};
					const expected = await applied(memory, "user-1", recover);
					const actual = await applied(redis, "user-1", recover);
					const shape = (answer: MfaSubjectRecoveryAnswer) => ({ ...answer, recoveryId: "" });
					expect(shape(actual), `step ${step}`).toEqual(shape(expected));
				} else {
					await resetSubject(memory, "user-1");
					await resetSubject(redis, "user-1");
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

	it("holds hard from the reservation that brings the run to the limit, through an exempt success, a void of that reservation and another exempt success, as core's store does", async () => {
		// The random walk seldom reaches the hard limit; this walks its edge.
		const four: MfaLockoutPolicy = {
			...POLICY,
			threshold: 4,
			baseSeconds: 60,
			maxSeconds: 60,
			weeklyBudget: 1000,
			hardLimit: 4,
		};
		const t = Math.floor(Date.now() / 1000) * 1000;
		const answers: Array<Array<string | null>> = [];
		for (const store of [createMemoryMfaTransactionStore(), storeAt(freshPrefix())]) {
			const seen: Array<string | null> = [];
			const reserve = async (at: number): Promise<string | null> => {
				const r = await store.reserveSubjectAttempt("user-1", at, four);
				seen.push(r.ok ? "ok" : r.hold);
				return r.ok ? r.reservation : null;
			};
			for (let i = 0; i < 3; i++) {
				const r = await reserve(t + i);
				if (r !== null) await store.settleSubjectAttempt("user-1", r, "failure");
			}
			const inFlight = await reserve(t + 3);
			await store.noteExemptSuccess("user-1", t + 4, four);
			await reserve(t + 5);
			if (inFlight !== null) await store.settleSubjectAttempt("user-1", inFlight, "void");
			await store.noteExemptSuccess("user-1", t + 6, four);
			for (let i = 0; i < 3; i++) {
				const r = await reserve(t + 7 + i);
				if (r !== null) await store.settleSubjectAttempt("user-1", r, "failure");
			}
			await reserve(t + 10);
			answers.push(seen);
		}
		expect(answers[1]).toEqual(answers[0]);
		expect(answers[0]).toEqual(["ok", "ok", "ok", "ok", "hard", "hard", "hard", "hard", "hard"]);
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
			await store.noteExemptSuccess("user-1", t + 30, POLICY);
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
	it("keeps it in a key of its own with no TTL, which a reset leaves and a consume removes", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = `${prefix}proof:{${keyPart("user-1")}}`;
		await store.requireEmailProofAtNextBinding("user-1");
		expect(await first().pttl(key)).toBe(-1);
		await store.reserveSubjectAttempt("user-1", Date.now(), POLICY);
		await resetSubject(store, "user-1");
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[key, `${prefix}recovery:{${keyPart("user-1")}}`].sort(),
		);
		expect(await store.consumeEmailProofRequirement("user-1")).toBe(true);
		expect(await first().exists(key)).toBe(0);
	});
});

describe("createRedisMfaTransactionStore — a session's account-email proof", () => {
	const proofKey = (prefix: string, subject: string, sid: string): string =>
		`${prefix}session-proof:{${keyPart(subject)}}:${keyPart(sid)}`;

	it("keeps it in a string of its own, <prefix>session-proof:{<subject>}:<sid>, holding when it was given and its end, expiring at its end on the store's clock", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = Date.now();
		const until = now + 10 * MINUTE;
		await store.recordSessionEmailProof("user-1", "sid-1", now, until);
		const key = proofKey(prefix, "user-1", "sid-1");
		expect(await first().keys(`${prefix}*`)).toEqual([key]);
		expect(await first().type(key)).toBe("string");
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual({
			provedAtMs: now,
			untilMs: until,
		});
		const ttl = await first().pttl(key);
		expect(ttl).toBeGreaterThan(9 * MINUTE);
		expect(ttl).toBeLessThanOrEqual(10 * MINUTE);
	});

	it("sets the key's lifetime from the store's own clock: a store whose clock runs behind keeps it longer, to the same end", async () => {
		const prefix = freshPrefix();
		const behind = createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(first()),
			keyPrefix: prefix,
			now: () => Date.now() - 5 * MINUTE,
		});
		const now = Date.now();
		await behind.recordSessionEmailProof("user-1", "sid-1", now - 5 * MINUTE, now + 10 * MINUTE);
		expect(await first().pttl(proofKey(prefix, "user-1", "sid-1"))).toBeGreaterThan(14 * MINUTE);
	});

	it("answers a proof past its end on its own clock as absent, though the server still holds it", async () => {
		const prefix = freshPrefix();
		const onTime = storeAt(prefix);
		const ahead = createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(first()),
			keyPrefix: prefix,
			now: () => Date.now() + 11 * MINUTE,
		});
		const now = Date.now();
		await onTime.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
		expect(await ahead.sessionEmailProofAt("user-1", "sid-1", now)).toBeNull();
		expect(await onTime.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
		expect(await first().exists(proofKey(prefix, "user-1", "sid-1"))).toBe(1);
	});

	it("answers a proof it cannot read back as absent: the user proves again", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = proofKey(prefix, "user-1", "sid-1");
		const now = Date.now();
		for (const value of [
			"not json",
			"null",
			JSON.stringify({ provedAtMs: now }),
			JSON.stringify({ provedAtMs: String(now), untilMs: now + MINUTE }),
			JSON.stringify({ provedAtMs: now, untilMs: now + MINUTE + 0.5 }),
			JSON.stringify({ provedAtMs: -1, untilMs: now + MINUTE }),
			JSON.stringify({ provedAtMs: now, untilMs: now }),
		]) {
			await first().set(key, value, "PX", MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now), value).toBeNull();
		}
	});

	it("keeps it apart from the transactions, the subject lock and the requirement an operator reset records", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = Date.now();
		await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
		// A transaction of the same session, created and consumed beside it.
		await store.create(TX({ sid: "sid-1" }));
		expect(await store.consume("tx-1", 1)).not.toBeNull();
		await store.requireEmailProofAtNextBinding("user-1");
		await store.reserveSubjectAttempt("user-1", now, POLICY);
		await resetSubject(store, "user-1");
		expect(await store.consumeEmailProofRequirement("user-1")).toBe(true);
		expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[proofKey(prefix, "user-1", "sid-1"), `${prefix}recovery:{${keyPart("user-1")}}`].sort(),
		);
	});
});

describe("createRedisMfaTransactionStore — a subject's first-binding mark", () => {
	const markKey = (prefix: string, subject: string): string =>
		`${prefix}first-binding:{${keyPart(subject)}}`;

	/** A store over the first connection whose own clock is `offsetMs` off the host's. */
	const skewedStore = (prefix: string, offsetMs: number): MfaTransactionStore =>
		createRedisMfaTransactionStore({
			client: makeIoredisMfaTransactionStoreClient(first()),
			keyPrefix: prefix,
			now: () => Date.now() + offsetMs,
		});

	it("keeps it in a string of its own, <prefix>first-binding:{<subject>}, holding when it was noted and its end, expiring at its end on the server's clock", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = await serverClock(first)();
		const until = Math.floor(now) + 10 * MINUTE;
		await store.noteFirstBinding("user-1", Math.floor(now), until);
		const key = markKey(prefix, "user-1");
		expect(await first().keys(`${prefix}*`)).toEqual([key]);
		expect(await first().type(key)).toBe("string");
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual({
			atMs: Math.floor(now),
			untilMs: until,
		});
		expect(await deadlineOf(key)).toBe(until);
	});

	it("judges a mark on the server's clock alone: a replica whose clock runs ahead neither reads it as ended nor replaces it with an earlier one", async () => {
		const prefix = freshPrefix();
		const onTime = storeAt(prefix);
		const ahead = skewedStore(prefix, 11 * MINUTE);
		const now = Math.floor(await serverClock(first)());
		await onTime.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		expect(await ahead.firstBindingAt("user-1", now + 11 * MINUTE)).toBe(now);
		await ahead.noteFirstBinding("user-1", now - MINUTE, now + 20 * MINUTE);
		expect(await onTime.firstBindingAt("user-1", now)).toBe(now);
		expect(await deadlineOf(markKey(prefix, "user-1"))).toBe(now + 20 * MINUTE);
	});

	it("judges a note's bounds on the server's clock, whatever the replica's clock says", async () => {
		const prefix = freshPrefix();
		const behind = skewedStore(prefix, -20 * MINUTE);
		const ahead = skewedStore(prefix, 20 * MINUTE);
		const now = Math.floor(await serverClock(first)());
		// On the server's clock these stand, though each replica's clock says otherwise.
		await ahead.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		expect(await behind.firstBindingAt("user-1", now)).toBe(now);
		// And these do not, though each replica's clock admits them.
		await expect(
			behind.noteFirstBinding("user-2", now - 15 * MINUTE, now - MINUTE),
		).rejects.toThrow(RangeError);
		await expect(
			ahead.noteFirstBinding("user-2", now + 15 * MINUTE, now + 30 * MINUTE),
		).rejects.toThrow(RangeError);
		expect(await first().exists(markKey(prefix, "user-2"))).toBe(0);
	});

	it("keeps the later time and the later end: the key's value and deadline move only forward", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = Math.floor(await serverClock(first)());
		const key = markKey(prefix, "user-1");
		await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		// Earlier and ending sooner: nothing moves.
		await store.noteFirstBinding("user-1", now - MINUTE, now + 5 * MINUTE);
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual({
			atMs: now,
			untilMs: now + 10 * MINUTE,
		});
		expect(await deadlineOf(key)).toBe(now + 10 * MINUTE);
		// Earlier and ending later: the end moves, the time stays.
		await store.noteFirstBinding("user-1", now - MINUTE, now + 30 * MINUTE);
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual({
			atMs: now,
			untilMs: now + 30 * MINUTE,
		});
		expect(await deadlineOf(key)).toBe(now + 30 * MINUTE);
	});

	it("refuses to answer a mark it cannot read back: an outage, never no mark, quoting nothing it read, whatever its end looks like", async () => {
		// No mark lets a session's recorded witness stand: a mark read as
		// absent would trust the session it is there to distrust.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = markKey(prefix, "user-1");
		const now = Math.floor(await serverClock(first)());
		for (const value of [
			"not json",
			"null",
			JSON.stringify({ atMs: now }),
			JSON.stringify({ atMs: String(now), untilMs: now + MINUTE }),
			JSON.stringify({ atMs: now - 0.5, untilMs: now + MINUTE }),
			JSON.stringify({ atMs: -1, untilMs: now + MINUTE }),
			JSON.stringify({ atMs: now, untilMs: now + MINUTE + 0.5 }),
			JSON.stringify({ atMs: now + MINUTE, untilMs: now + MINUTE }),
			// An end that looks past is no excuse for a shape that is wrong.
			JSON.stringify({ untilMs: -1 }),
			JSON.stringify({ atMs: "x", untilMs: 1 }),
			JSON.stringify({ atMs: -5, untilMs: 1 }),
			JSON.stringify({ atMs: now, untilMs: 0 }),
			// Standing longer than any note may make it stand.
			JSON.stringify({ atMs: now, untilMs: now + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1 }),
			// A field a note never writes, the script's JSON reader and this
			// side's disagreeing on it or not.
			...odd(now),
		]) {
			await first().set(key, value, "PX", MINUTE);
			const read = store.firstBindingAt("user-1", now);
			await expect(read, value).rejects.toThrow(/MfaTransactionStore/);
			await expect(read, value).rejects.not.toThrow(RangeError);
			await expect(read, value).rejects.not.toThrow(/not json|atMs|untilMs/);
		}
	});

	it("replaces a mark it cannot read back with the next note", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = markKey(prefix, "user-1");
		const now = Math.floor(await serverClock(first)());
		for (const value of [
			"not json",
			JSON.stringify({ atMs: now + MINUTE }),
			JSON.stringify({ atMs: now - MINUTE, untilMs: now + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1 }),
			...odd(now - MINUTE),
		]) {
			await first().set(key, value, "PX", MINUTE);
			await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now), value.slice(0, 60)).toBe(now);
		}
	});

	it("replaces, never merges, a held value with a field a note never writes, however late its times", async () => {
		// Merged, its later times would stay, and this side refuses them as an
		// outage no note could then repair.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = markKey(prefix, "user-1");
		const now = Math.floor(await serverClock(first)());
		const held = { atMs: now + 6 * MINUTE, untilMs: now + 20 * MINUTE, x: 1 };
		await first().set(key, JSON.stringify(held), "PXAT", held.untilMs);
		await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual({
			atMs: now,
			untilMs: now + 10 * MINUTE,
		});
		expect(await deadlineOf(key)).toBe(now + 10 * MINUTE);
		expect(await store.firstBindingAt("user-1", now)).toBe(now);
	});

	it("refuses to read a key of another type, an outage, and a note overwrites it", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = markKey(prefix, "user-1");
		const now = Math.floor(await serverClock(first)());
		for (const [type, write] of [
			["hash", () => first().hset(key, "atMs", String(now))],
			["list", () => first().rpush(key, String(now))],
			["set", () => first().sadd(key, String(now))],
			["zset", () => first().zadd(key, now, "atMs")],
		] as const) {
			await first().del(key);
			await write();
			const read = store.firstBindingAt("user-1", now);
			await expect(read, type).rejects.toThrow();
			await expect(read, type).rejects.not.toThrow(RangeError);
			await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
			expect(await first().type(key), type).toBe("string");
			expect(await store.firstBindingAt("user-1", now), type).toBe(now);
		}
	});

	it("keeps a sound mark noted ahead of the server's clock, as one whose clock stepped back sees it: a note merges with it and never moves it back", async () => {
		// The script sees a mark noted before its server's clock stepped back
		// as one ahead of it. Implausible on the clock, it is still a mark.
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const key = markKey(prefix, "user-1");
		const now = Math.floor(await serverClock(first)());
		const held = { atMs: now + 6 * MINUTE, untilMs: now + 20 * MINUTE };
		await first().set(key, JSON.stringify(held), "PXAT", held.untilMs);
		await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		expect(JSON.parse((await first().get(key)) as string)).toStrictEqual(held);
		expect(await deadlineOf(key)).toBe(held.untilMs);
		// The store answers it; the caller's reading judges it on its own clock.
		expect(await store.firstBindingAt("user-1", now)).toBe(held.atMs);
	});

	it("answers a sound mark read on a server whose clock stepped back, rather than an outage", async () => {
		const prefix = freshPrefix();
		const client = makeIoredisMfaTransactionStoreClient(first());
		const stepped: MfaTransactionStoreClient = {
			...client,
			firstBindingMark: async (key) => {
				const read = await client.firstBindingMark(key);
				return { ...read, serverNowMs: read.serverNowMs - 10 * MINUTE };
			},
		};
		const store = createRedisMfaTransactionStore({ client: stepped, keyPrefix: prefix });
		const now = Math.floor(await serverClock(first)());
		await storeAt(prefix).noteFirstBinding("user-1", now, now + 20 * MINUTE);
		expect(await store.firstBindingAt("user-1", now)).toBe(now);
	});

	it("notes and reads through EVAL once the server has forgotten the scripts", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = Math.floor(await serverClock(first)());
		await store.noteFirstBinding("user-1", now - MINUTE, now + 10 * MINUTE);
		await store.firstBindingAt("user-1", now);
		await first().script("FLUSH");
		await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		expect(await store.firstBindingAt("user-1", now)).toBe(now);
		expect(
			await first().script("EXISTS", MFA_FIRST_BINDING_NOTE.sha, MFA_FIRST_BINDING_READ.sha),
		).toEqual([1, 1]);
	});

	it("rejects a note and a read when the server cannot be reached: an outage, never no mark", async () => {
		const unreachable = first().duplicate({ lazyConnect: true, enableOfflineQueue: false });
		try {
			const store = storeAt(freshPrefix(), unreachable);
			const now = Date.now();
			await expect(store.noteFirstBinding("user-1", now, now + 10 * MINUTE)).rejects.toThrow();
			await expect(store.firstBindingAt("user-1", now)).rejects.toThrow();
		} finally {
			unreachable.disconnect();
		}
	});

	it("keeps it apart from the transactions, the subject lock, the requirement and a session's proof", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const now = Math.floor(await serverClock(first)());
		await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
		await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
		await store.create(TX({ sid: "sid-1" }));
		expect(await store.consume("tx-1", 1)).not.toBeNull();
		await store.requireEmailProofAtNextBinding("user-1");
		await store.reserveSubjectAttempt("user-1", now, POLICY);
		await resetSubject(store, "user-1");
		expect(await store.consumeEmailProofRequirement("user-1")).toBe(true);
		expect(await store.firstBindingAt("user-1", now)).toBe(now);
		expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(
			[
				markKey(prefix, "user-1"),
				`${prefix}session-proof:{${keyPart("user-1")}}:${keyPart("sid-1")}`,
				`${prefix}recovery:{${keyPart("user-1")}}`,
			].sort(),
		);
	});
});

describe("createRedisMfaTransactionStore — a subject's lease, recovery and floor", () => {
	const keysOf = (prefix: string, subject = "user-1") => {
		const tag = `{${keyPart(subject)}}`;
		return {
			lock: `${prefix}lock:${tag}`,
			week: `${prefix}week:${tag}`,
			recovery: `${prefix}recovery:${tag}`,
			lease: `${prefix}lease:${tag}`,
		};
	};

	it("has no clearSubjectState, on the store or its client: an applied recovery is the one way the lock state ends", () => {
		const client = makeIoredisMfaTransactionStoreClient(first());
		expect("clearSubjectState" in storeAt(freshPrefix())).toBe(false);
		expect("clearSubjectState" in client).toBe(false);
	});

	it("keeps the lease and the recovery hash under the subject's tag beside its lock and week", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const keys = keysOf(prefix);
		await store.reserveSubjectAttempt("user-1", Date.now() - MINUTE, POLICY);
		const lease = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		await store.raiseRecoverySetFloor("user-1", { setGeneration: 2, leaseToken: lease.token });
		expect((await first().keys(`${prefix}*`)).sort()).toEqual(Object.values(keys).sort());
		expect(await first().get(keys.lease)).toBe(lease.token);
		const ttl = await first().pttl(keys.lease);
		expect(ttl).toBeGreaterThan(0);
		expect(ttl).toBeLessThanOrEqual(60_000);
		expect(await first().hgetall(keys.recovery)).toEqual({ floor: "2" });
	});

	it("gives the recovery hash a deadline while it holds authorizations alone, and none once it holds a generation or a floor", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const { recovery } = keysOf(prefix);
		const ends = Math.floor(Date.now()) + 10 * MINUTE;
		await store.authorizeSubjectRecovery("user-1", {
			operation: "recover",
			sid: "sid-1",
			recoveryId: "r-1",
			expiresAtMs: ends,
		});
		expect(await deadlineOf(recovery)).toBe(ends + MFA_CLOCK_SKEW_ALLOWANCE_MS);
		expect(await applied(store, "user-1", { operation: "recover" })).toMatchObject({
			outcome: "applied",
		});
		expect(await deadlineOf(recovery)).toBe(-1);

		const other = keysOf(prefix, "user-2").recovery;
		const lease = await store.acquireSubjectLease("user-2", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		await store.raiseRecoverySetFloor("user-2", { setGeneration: 1, leaseToken: lease.token });
		expect(await deadlineOf(other)).toBe(-1);
	});

	it("answers a generation, a floor or an authorization it cannot read as an outage, never as none", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const { recovery } = keysOf(prefix);
		const lease = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		await first().hset(recovery, "g", "x");
		await expect(store.subjectGeneration("user-1")).rejects.toThrow(/generation/);
		await expect(
			store.acquireSubjectLease("user-2", { ttlMs: 60_000, generation: 0 }),
		).resolves.toMatchObject({ outcome: "acquired" });
		await expect(
			store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 }),
		).rejects.toThrow(/subject state/);
		await first().hset(recovery, "g", "1", "floor", "x");
		await expect(store.recoverySetFloor("user-1")).rejects.toThrow(/floor/);
		await expect(
			store.raiseRecoverySetFloor("user-1", { setGeneration: 2, leaseToken: lease.token }),
		).rejects.toThrow(/subject state/);
		await first().hset(recovery, "floor", "1", `a:recover:${keyPart("sid-1")}`, "garbage");
		await expect(
			store.applySubjectRecovery("user-1", {
				operation: "recover",
				sid: "sid-1",
				nowMs: Date.now(),
				leaseToken: lease.token,
				sessionsBoundaryMs: undefined,
				guessableBoundSinceMs: null,
			}),
		).rejects.toThrow(/subject state/);
	});

	it("answers a lease with no deadline, which it never writes, as an outage", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		await first().set(keysOf(prefix).lease, "someone");
		await expect(
			store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 }),
		).rejects.toThrow(/lease script/);
	});

	it("ends at a reset a lock state the scripts cannot read", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const { lock, week } = keysOf(prefix);
		await store.reserveSubjectAttempt("user-1", Date.now(), POLICY);
		await first().hset(lock, "r:x", "garbage");
		await expect(store.reserveSubjectAttempt("user-1", Date.now(), POLICY)).rejects.toThrow(
			/subject state/,
		);
		await resetSubject(store, "user-1");
		expect(await first().exists(lock, week)).toBe(0);
		expect((await store.reserveSubjectAttempt("user-1", Date.now(), POLICY)).ok).toBe(true);
	});

	/** Each key's serialized value and absolute deadline: equal only for keys left byte for byte as they were. */
	const snapshot = async (keys: readonly string[]) =>
		Promise.all(
			keys.map(async (key) => ({
				key,
				value: await first().dumpBuffer(key),
				deadline: await deadlineOf(key),
			})),
		);

	/** A subject with failures in its run and week, a pending recover and reset authorized, and the lease held. */
	async function primed(prefix: string): Promise<{ store: MfaTransactionStore; token: string }> {
		const store = storeAt(prefix);
		for (let i = 0; i < 3; i++) {
			const reserved = await store.reserveSubjectAttempt("user-1", Date.now() - HOUR + i, POLICY);
			if (!reserved.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
		}
		for (const operation of ["recover", "reset"] as const) {
			await store.authorizeSubjectRecovery("user-1", {
				operation,
				sid: operation === "recover" ? "sid-1" : undefined,
				recoveryId: `${operation}-1`,
				expiresAtMs: Date.now() + 10 * MINUTE,
			});
		}
		const lease = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		return { store, token: lease.token };
	}

	const applyOf = (
		store: MfaTransactionStore,
		operation: "recover" | "reset",
		leaseToken: string,
	): Promise<MfaSubjectRecoveryAnswer> =>
		store.applySubjectRecovery("user-1", {
			operation,
			sid: operation === "recover" ? "sid-1" : undefined,
			nowMs: Date.now(),
			leaseToken,
			sessionsBoundaryMs: operation === "recover" ? Date.now() : undefined,
			guessableBoundSinceMs: operation === "recover" ? null : undefined,
		});

	it.each([
		["a generation that is not a count", "g", "x"],
		["a generation with a leading zero", "g", "01"],
		["a floor with a leading zero", "floor", "01"],
		["another session's authorization it cannot read", `a:recover:${keyPart("sid-2")}`, "garbage"],
		["an applied authorization at generation 0", `a:recover:${keyPart("sid-2")}`, "a|0|1|r"],
		["a generation past the safe integers", "g", "9007199254740992"],
		[
			"an applied authorization past the safe integers",
			`a:recover:${keyPart("sid-2")}`,
			"a|9007199254740992|1|r",
		],
		[
			"a pending authorization ending past the Date range",
			`a:recover:${keyPart("sid-2")}`,
			"p|8640000000000001|r",
		],
		[
			"an applied authorization ending past the Date range",
			`a:recover:${keyPart("sid-2")}`,
			"a|1|8640000000000001|r",
		],
	])(
		"answers a recover and a reset an outage when the recovery hash holds %s, leaving the lock, week and recovery keys as they were",
		async (_label, field, value) => {
			const prefix = freshPrefix();
			const { store, token } = await primed(prefix);
			const keys = keysOf(prefix);
			await first().hset(keys.recovery, field, value);
			const before = await snapshot([keys.lock, keys.week, keys.recovery]);
			for (const operation of ["recover", "reset"] as const) {
				await expect(applyOf(store, operation, token), operation).rejects.toThrow(/subject state/);
				expect(await snapshot([keys.lock, keys.week, keys.recovery]), operation).toEqual(before);
			}
		},
	);

	it("answers an authorize an outage when the recovery hash holds another authorization it cannot read, writing nothing", async () => {
		const prefix = freshPrefix();
		const { store } = await primed(prefix);
		const { recovery } = keysOf(prefix);
		await first().hset(recovery, `a:recover:${keyPart("sid-2")}`, "garbage");
		const before = await snapshot([recovery]);
		await expect(
			store.authorizeSubjectRecovery("user-1", {
				operation: "recover",
				sid: "sid-3",
				recoveryId: "r-3",
				expiresAtMs: Date.now() + 10 * MINUTE,
			}),
		).rejects.toThrow(/subject state/);
		expect(await snapshot([recovery])).toEqual(before);
	});

	it("reads a generation or a floor with a leading zero as an outage, in the reads and in the scripts alike", async () => {
		const prefix = freshPrefix();
		const store = storeAt(prefix);
		const { recovery } = keysOf(prefix);
		const lease = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		await first().hset(recovery, "g", "01", "floor", "02");
		await expect(store.subjectGeneration("user-1")).rejects.toThrow(/generation/);
		await expect(
			store.acquireSubjectLease("user-2", { ttlMs: 60_000, generation: 0 }),
		).resolves.toMatchObject({ outcome: "acquired" });
		await expect(
			store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 1 }),
		).rejects.toThrow(/subject state/);
		await expect(store.recoverySetFloor("user-1")).rejects.toThrow(/floor/);
		await expect(
			store.raiseRecoverySetFloor("user-1", { setGeneration: 3, leaseToken: lease.token }),
		).rejects.toThrow(/subject state/);
		expect(await first().hget(recovery, "floor")).toBe("02");
	});

	it("answers a release, and an acquire under a generation past the safe integers, an outage", async () => {
		const prefix = freshPrefix();
		const { store, token } = await primed(prefix);
		const { lease, recovery } = keysOf(prefix);
		await first().persist(lease);
		await expect(store.releaseSubjectLease("user-1", token)).rejects.toThrow(/lease/);
		expect(await first().get(lease)).toBe(token);
		await first().hset(recovery, "g", "9007199254740992");
		await expect(
			store.acquireSubjectLease("user-2", { ttlMs: 60_000, generation: 0 }),
		).resolves.toMatchObject({ outcome: "acquired" });
		await first().del(lease);
		await expect(
			store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 }),
		).rejects.toThrow(/subject state/);
	});

	/**
	 * A connection on which every `PTTL` the release, apply and floor scripts ask answers 0: the
	 * lease at its last millisecond, its token still held. The scripts run on the real server.
	 */
	const atLastMillisecond = (): Redis => {
		const real = first();
		const scripts = [
			MFA_SUBJECT_LEASE_RELEASE,
			MFA_SUBJECT_RECOVERY_APPLY,
			MFA_RECOVERY_SET_FLOOR_RAISE,
		];
		const zeroed = (source: string): string =>
			source
				.replaceAll("redis.call('PTTL', KEYS[1])", "0")
				.replaceAll("redis.call('PTTL', key)", "0");
		const run = (script: (typeof scripts)[number] | undefined, rest: unknown[]) => {
			if (script === undefined) throw new Error("a script the stub does not stand in for");
			return real.eval(zeroed(script.source), ...(rest as [number, ...string[]]));
		};
		return new Proxy(real, {
			get(target, property, receiver) {
				if (property === "evalsha") {
					return (sha: string, ...rest: unknown[]) =>
						run(
							scripts.find((script) => script.sha === sha),
							rest,
						);
				}
				if (property === "eval") {
					return (source: string, ...rest: unknown[]) =>
						run(
							scripts.find((script) => script.source === source),
							rest,
						);
				}
				const value = Reflect.get(target, property, receiver);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
	};

	it("answers a release at the lease's last millisecond false, as a lease that lapsed, never an outage", async () => {
		const prefix = freshPrefix();
		const { token } = await primed(prefix);
		const store = storeAt(prefix, atLastMillisecond());
		expect(await store.releaseSubjectLease("user-1", token)).toBe(false);
	});

	it("refuses an apply and a floor raise at the lease's last millisecond lease_not_held, never an outage", async () => {
		const prefix = freshPrefix();
		const { token } = await primed(prefix);
		const store = storeAt(prefix, atLastMillisecond());
		expect(await applyOf(store, "reset", token)).toMatchObject({
			outcome: "refused",
			reason: "lease_not_held",
		});
		expect(
			await store.raiseRecoverySetFloor("user-1", { setGeneration: 1, leaseToken: token }),
		).toEqual({ outcome: "refused", reason: "lease_not_held" });
	});

	it("refuses an apply, and a floor raise, under a lease key with no deadline, which it never writes", async () => {
		const prefix = freshPrefix();
		const { store, token } = await primed(prefix);
		const { lease } = keysOf(prefix);
		await first().persist(lease);
		expect(await applyOf(store, "reset", token)).toMatchObject({
			outcome: "refused",
			reason: "lease_not_held",
		});
		expect(
			await store.raiseRecoverySetFloor("user-1", { setGeneration: 1, leaseToken: token }),
		).toEqual({ outcome: "refused", reason: "lease_not_held" });
	});

	it("answers a lease at its last millisecond as busy for at least one more, and one with no deadline as an outage", async () => {
		const keys = keysOf("mfat:stub:");
		const input = { token: "t", ttlMs: 60_000, generation: 0 };
		const answering = (reply: unknown) =>
			makeIoredisMfaTransactionStoreClient({
				evalsha: async () => reply,
				eval: async () => reply,
			} as unknown as Redis);
		await expect(answering(["busy", 0]).acquireSubjectLease(keys, input)).resolves.toEqual({
			outcome: "busy",
			retryAfterMs: 1,
		});
		await expect(answering(["busy", 250]).acquireSubjectLease(keys, input)).resolves.toEqual({
			outcome: "busy",
			retryAfterMs: 250,
		});
		await expect(answering(["busy", -1]).acquireSubjectLease(keys, input)).rejects.toThrow(
			/lease script/,
		);
	});
});
