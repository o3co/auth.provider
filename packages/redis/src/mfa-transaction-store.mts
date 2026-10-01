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
 * Redis {@link MfaTransactionStore}: the single-use record of each
 * second-factor ceremony, the subject lock that bounds guessable proofs and
 * its authorized recovery, a subject's generation, lease and recovery-set
 * floor, the email proof an operator reset requires, the account-email proof given in a
 * session, and a subject's first-binding mark (see
 * packages/core/docs/adr/2026-09-25-multi-factor-authentication.md).
 *
 * ```text
 * <keyPrefix>tx:{<id>}                          HASH   one transaction, expiring at its expiresAtMs
 * <keyPrefix>binding:{<digest>}                ZSET   a binding's transactions, scored by expiresAtMs, expiring at the latest
 * <keyPrefix>lock:{<subject>}                   HASH   the lockout run, reservations in flight, the hard hold
 * <keyPrefix>week:{<subject>}                   ZSET   the weekly window: one member per attempt, scored by time
 * <keyPrefix>recovery:{<subject>}               HASH   the generation, the recovery-set floor, the recovery authorizations
 * <keyPrefix>lease:{<subject>}                  STRING the lease holder's token, expiring at the lease's end
 * <keyPrefix>proof:{<subject>}                  STRING the email-proof requirement, with no TTL
 * <keyPrefix>session-proof:{<subject>}:<sid>    STRING a session's account-email proof, expiring at its end
 * <keyPrefix>first-binding:{<subject>}          STRING a subject's first-binding mark, expiring at its end
 * ```
 *
 * `<id>`, `<subject>` and `<sid>` are base64url of their JSON (`internal/mfa-keys.mts`);
 * `<digest>` is base64url of the SHA-256 of the binding, kind and id, so the
 * express session id is copied into no key.
 * A subject's lock, week, recovery hash and lease share its hash tag, so each
 * operation on them is one script on one Cluster slot. The recovery hash
 * carries no TTL once it holds a generation or a floor (losing either would
 * refuse a writer or bring an older recovery-code set back); before that it
 * expires a day after its latest authorization ends. A lease and an
 * authorization end on the server's clock. Every operation a race could split is one script
 * (`makeIoredisClients`): insert-only create, compare-and-set update,
 * `reserveAttempt`, `takeChallenge`, `consume`, and each lockout step, which
 * reads, decides and writes the subject state at once.
 *
 * A binding holds at most `MFA_MAX_TRANSACTIONS_PER_BINDING` live
 * transactions, kept in its index: one member per transaction,
 * `<incarnation>:<id key part>`, scored by its `expiresAtMs` exactly (so the
 * one ended is the one core's in-process store ends, within one millisecond
 * too; at one instant, which goes is either store's choice). This adapter
 * holds the cap's policy — N, which goes, the order of the steps and what a
 * failed step costs — and the client only its three one-script primitives.
 * `create` writes the
 * transaction, then one script adds its member and takes out those with the
 * soonest expiries past the cap, never the new one; each taken out is
 * deleted by a script that compares its `incarnation`, so a member left
 * behind never deletes a transaction created again under its id, for any
 * binding. `consume`, and a reservation past `max`, take the member out.
 * The index key expires at the latest deadline it holds, set again whenever a
 * member is added or removed, and an empty one is gone, so it never outlives
 * the transactions it names. An expired transaction's
 * member stays until it is taken out first: its deadline is the soonest. The
 * transactions sit on slots of their own, so these are separate steps, not
 * one atomic one. While creates are in flight a binding may hold more than
 * the cap; once they have answered it holds at most the cap, and only a step
 * that failed leaves an excess, until it expires: a create refused at its
 * index step has already written its transaction, and an eviction that fails
 * (warned, `mfa_transaction_evict_failed`; the create still answers) leaves
 * the one it would have ended. A member that failed to leave (warned,
 * `mfa_transaction_unindex_failed`), or one added after its transaction was
 * already consumed (a consume landing between a create's write and its index
 * step, which no caller can do before `create` hands it the id), scores late
 * and counts for a transaction that is gone until its deadline: meanwhile a
 * create past the cap may end a live transaction early. A server whose clock
 * runs ahead of the callers' by more than a transaction's lifetime finds
 * every deadline in an index past, so `PEXPIREAT` drops the index as it is
 * written and the binding goes unbounded while that lasts, each transaction
 * still ending at its own expiry: callers' clocks and the server's must
 * agree (NTP).
 *
 * A transaction is written and read back through core's
 * `newMfaTransactionRecord`, so it has the in-process store's shape and rules.
 * One that does not read back is absent: the user starts again, rather than
 * getting a 503 for the rest of its lifetime. A hash field that is no
 * transaction's is not read, and a lock-hash field of no kind the scripts
 * know is ignored: neither can loosen a limit the store keeps.
 *
 * Two clocks: the key expires on the server's clock (`PEXPIREAT`, rounded up),
 * and every operation also answers a transaction at or past `expiresAtMs` on
 * this side's clock as absent, so a server running behind cannot let a
 * ceremony spend an attempt, take a challenge or complete past its deadline.
 * Lockout answers are judged on the time the caller passes; what the scripts
 * forget and Redis reclaims is judged no later than the server's clock less
 * `MFA_CLOCK_SKEW_ALLOWANCE_MS`. While a run is counted (until a success, an
 * exempt success before the hard hold or an applied recovery) or the hard
 * hold stands (until an applied recovery) the subject's keys carry no TTL,
 * and a subject state a script cannot read is refused, never read as empty.
 *
 * The requirement must last as enrolled factors do: it has no TTL, and the
 * module runs the factor store's durability check.
 *
 * A session's proof is JSON `{provedAtMs, untilMs}` written with `PX` on
 * this side's clock (`untilMs` less `now`, rounded up), and answered absent
 * at or past `untilMs` on that clock too. One that does not read back is
 * absent: losing a proof fails closed — the user proves again.
 *
 * A subject's first-binding mark is JSON `{atMs, untilMs}` judged on one
 * clock, the Redis server's (`TIME` in its scripts): its end, which mark a
 * note keeps (the later time and the later end) and the key's deadline
 * (`PXAT` its end). This side's clock decides none of them, so a replica
 * whose clock runs ahead or behind neither ends a mark early nor replaces it
 * with an earlier one, and a mark whose time sits ahead of the server's clock
 * (a clock stepped back) is still merged and answered: the caller's reading
 * judges that. A value that does not read back as a mark, whatever its end
 * looks like, or a key of another type, is an outage, never absent: an
 * absent mark trusts the session it is there to distrust. A note replaces
 * either.
 */

import { createHash, randomBytes } from "node:crypto";
import {
	checkFirstBindingNote,
	checkFirstBindingQuestion,
	checkMfaLockoutPolicy,
	checkMfaTransactionTransitions,
	checkMfaVersionAdvances,
	checkRecoverySetFloorRaise,
	checkSessionEmailProof,
	checkSessionEmailProofQuestion,
	checkSubjectLeaseRelease,
	checkSubjectLeaseRequest,
	checkSubjectQuestion,
	checkSubjectRecoveryApplication,
	checkSubjectRecoveryAuthorization,
	consoleLogger,
	DEFAULT_CLOCK_SKEW_MS,
	defineModule,
	type EventLogger,
	type FirstBindingMark,
	firstBindingAnswer,
	isStorableExpiry,
	loggableError,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	MFA_MAX_TRANSACTIONS_PER_BINDING,
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	type MfaSubjectRecoveryOperation,
	type MfaTransaction,
	type MfaTransactionBinding,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	mfaTransactionPatchWrites,
	newMfaTransactionRecord,
	readMfaSubjectRecoveryAnswer,
	type SessionEmailProof,
	sessionEmailProofAnswer,
} from "@o3co/auth-provider-core";
import type {
	MfaRemovedTransaction,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
} from "./clients.mjs";
import { checkRedisMfaStoreDurability } from "./internal/mfa-durability.mjs";
import { checkMfaKeyPrefix, mfaKeyPart } from "./internal/mfa-keys.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/** The key namespace `redisMfaTransactionStore.keyPrefix` defaults to. */
export const DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX = "mfat:";

export interface RedisMfaTransactionStoreOptions {
	readonly client: MfaTransactionStoreClient;
	/** Outer namespace; each key's family and hash tag follow it. No brace. Default `mfat:`. */
	readonly keyPrefix?: string;
	/**
	 * The clock a transaction expires by on this side, in epoch milliseconds:
	 * `create` refuses an expiry at or before it, and a read answers a
	 * transaction at or past its `expiresAtMs` on it as absent, whatever the
	 * server's clock says. A session's proof is judged on it too; a subject's
	 * first-binding mark is not (the server's clock decides it). Default
	 * `Date.now`.
	 */
	readonly now?: () => number;
	/**
	 * Where a binding index step that failed after its operation answered is
	 * warned (`mfa_transaction_evict_failed`, `mfa_transaction_unindex_failed`).
	 * Default `consoleLogger`.
	 */
	readonly logger?: Pick<EventLogger, "warn">;
}

/** How each patch field is written into the hash. */
const PATCH_FIELD_TEXT: Readonly<Record<keyof MfaTransactionPatch, (value: unknown) => string>> = {
	enrollment: (value) => value as string,
	emailProof: (value) => JSON.stringify(value),
	challenge: (value) => JSON.stringify(value),
	pendingEnrollment: (value) => JSON.stringify(value),
};

/** The fields of a new transaction's hash; `index` is its binding's digest. */
function fieldsOf(
	record: MfaTransaction,
	incarnation: string,
	index: string,
): Record<string, string> {
	const fields: Record<string, string> = {
		id: record.id,
		incarnation,
		index,
		version: String(record.version),
		attempts: "0",
		enrollment: record.enrollment,
		emailProof: JSON.stringify(record.emailProof),
		// The deadline again, for the reserve and take scripts to read with
		// `tonumber` (it reads back as the same double): they never decode
		// `record`, since `cjson` refuses what `JSON.parse` accepts (a
		// lone-surrogate escape, deep nesting).
		expiresAtMs: String(record.expiresAtMs),
		// What never changes after `create`, as one JSON document; absent is null.
		record: JSON.stringify({
			purpose: record.purpose,
			binding: record.binding,
			subject: record.subject,
			sid: record.sid ?? null,
			continuation: record.continuation ?? null,
			redirectTo: record.redirectTo ?? null,
			acrValues: record.acrValues ?? null,
			createdAtMs: record.createdAtMs,
			expiresAtMs: record.expiresAtMs,
		}),
	};
	if (record.challenge !== undefined) fields.challenge = JSON.stringify(record.challenge);
	if (record.pendingEnrollment !== undefined) {
		fields.pendingEnrollment = JSON.stringify(record.pendingEnrollment);
	}
	return fields;
}

/** A counter as the hash keeps it: decimal text of a safe non-negative integer; NaN otherwise. */
const countOf = (text: string | undefined): number =>
	text !== undefined && /^(0|[1-9][0-9]*)$/.test(text) ? Number(text) : Number.NaN;

const parsed = (text: string | undefined): unknown =>
	text === undefined ? undefined : JSON.parse(text);

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The transaction `fields` hold, rebuilt through `newMfaTransactionRecord` as
 * plain data, or `null` when they hold nothing, another id's, what that
 * function refuses, or a transaction at or past its `expiresAtMs` at `nowMs`
 * (a server whose clock runs behind still holds the key).
 */
function transactionOf(
	fields: Readonly<Record<string, string>>,
	id: string,
	nowMs: number,
): MfaTransaction | null {
	if (fields.id !== id) return null;
	try {
		const fixed = parsed(fields.record);
		const attempts = countOf(fields.attempts);
		if (!isObject(fixed) || !Number.isSafeInteger(attempts)) return null;
		if (typeof fixed.expiresAtMs !== "number" || !Number.isFinite(fixed.expiresAtMs)) return null;
		if (fixed.expiresAtMs <= nowMs) return null;
		const record = newMfaTransactionRecord({
			id,
			purpose: fixed.purpose,
			binding: fixed.binding,
			subject: fixed.subject,
			sid: fixed.sid ?? undefined,
			continuation: fixed.continuation ?? undefined,
			redirectTo: fixed.redirectTo ?? undefined,
			enrollment: fields.enrollment,
			emailProof: parsed(fields.emailProof),
			acrValues: fixed.acrValues ?? undefined,
			challenge: parsed(fields.challenge),
			pendingEnrollment: parsed(fields.pendingEnrollment),
			attempts: 0,
			createdAtMs: fixed.createdAtMs,
			expiresAtMs: fixed.expiresAtMs,
			version: countOf(fields.version),
		} as MfaTransaction);
		// Plain data, as the in-process store answers: the continuation's
		// check answers a frozen copy.
		return structuredClone({ ...record, attempts });
	} catch {
		return null;
	}
}

/** A binding's digest: base64url of the SHA-256 of its kind and id, so no key copies the id. */
const bindingDigest = (binding: MfaTransactionBinding): string =>
	createHash("sha256")
		.update(JSON.stringify([binding.kind, binding.id]))
		.digest("base64url");

/** Text this store wrote as a key part, a digest or an incarnation: base64url, nothing else. */
const isKeyText = (text: string): boolean => /^[A-Za-z0-9_-]+$/.test(text);

const isWholeVersion = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** The challenge `text` holds, to its known fields, or `null`. */
function challengeOf(text: string | null): MfaTransaction["challenge"] | null {
	if (text === null) return null;
	try {
		const [write] = mfaTransactionPatchWrites({
			challenge: JSON.parse(text) as NonNullable<MfaTransaction["challenge"]>,
		});
		return (write?.[1] as MfaTransaction["challenge"]) ?? null;
	} catch {
		return null;
	}
}

/**
 * The session proof `text` holds, held on `storeNowMs` to the rule it was
 * written under (`checkSessionEmailProof`), or `null`.
 */
function sessionProofOf(
	text: string | null,
	subject: string,
	sid: string,
	storeNowMs: number,
): SessionEmailProof | null {
	if (text === null) return null;
	try {
		const value: unknown = JSON.parse(text);
		if (!isObject(value)) return null;
		const { provedAtMs, untilMs } = value;
		checkSessionEmailProof(subject, sid, provedAtMs, untilMs, storeNowMs);
		return { provedAtMs: provedAtMs as number, untilMs: untilMs as number };
	} catch {
		return null;
	}
}

/** The fields a note writes, and no other. */
const MARK_FIELDS: ReadonlySet<string> = new Set(["atMs", "untilMs"]);

/**
 * The first-binding mark `text` holds, or `null` when there is none. Throws,
 * naming nothing it read, when it holds no mark a note could have written:
 * `atMs` and `untilMs` and no other field — a note writes none, and the
 * script that keeps the mark need not decode one — in the shape
 * `checkFirstBindingNote` holds a note to, judged before its end is. Where
 * its time sits on the server's clock is the caller's reading to judge.
 */
function firstBindingMarkOf(text: string | null, subject: string): FirstBindingMark | null {
	if (text === null) return null;
	const unreadable = (): never => {
		throw new Error("MfaTransactionStore: a first-binding mark it cannot read");
	};
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return unreadable();
	}
	if (!isObject(value) || !Object.keys(value).every((key) => MARK_FIELDS.has(key))) {
		return unreadable();
	}
	const { atMs, untilMs } = value;
	try {
		checkFirstBindingNote(subject, atMs, untilMs);
	} catch {
		return unreadable();
	}
	return { atMs: atMs as number, untilMs: untilMs as number };
}

const flag = (text: string | undefined): boolean | undefined =>
	text === "1" ? true : text === "0" ? false : undefined;

/** A generation as the apply script answers it: canonical decimal text of a safe whole number from 1; `undefined` for anything else. */
const generationText = (text: string | undefined): number | undefined =>
	text !== undefined && /^[1-9][0-9]*$/.test(text) && Number.isSafeInteger(Number(text))
		? Number(text)
		: undefined;

/** The apply script's reply in the port's terms, for core's reading to hold to the port. */
function recoveryAnswerOf(reply: readonly string[]): unknown {
	const [outcome, a, b, c, d, e, f] = reply;
	if (outcome === "refused") return { outcome, reason: a, hard: flag(b) };
	if (outcome === "already") {
		return {
			outcome: "already_applied",
			recoveryId: a,
			generation: generationText(b),
			hard: flag(c),
		};
	}
	if (outcome === "applied") {
		return {
			outcome,
			recoveryId: a,
			generation: generationText(b),
			cleared: { week: flag(c), run: flag(d), hard: flag(e) },
			hard: flag(f),
		};
	}
	return undefined;
}

/** An authorization's field in the recovery hash: its operation and its sid (`-` for none). */
const recoveryField = (operation: MfaSubjectRecoveryOperation, sid: string | undefined): string =>
	`a:${operation}:${sid === undefined ? "-" : mfaKeyPart(sid)}`;

/** A count the recovery hash keeps (the generation, the floor): absent is 0; anything but decimal text of a safe whole number is an outage. */
function countIn(text: string | null, what: string): number {
	if (text === null) return 0;
	const count = countOf(text);
	if (!Number.isSafeInteger(count))
		throw new Error(`MfaTransactionStore: a ${what} it cannot read`);
	return count;
}

function checkInstant(nowMs: number, operation: string): void {
	if (!isStorableExpiry(nowMs)) {
		throw new RangeError(
			`MfaTransactionStore.${operation}: nowMs must be a finite instant within the Date range`,
		);
	}
}

export function createRedisMfaTransactionStore(
	options: RedisMfaTransactionStoreOptions,
): MfaTransactionStore {
	const { client } = options;
	const clock = options.now ?? Date.now;
	const keyPrefix = checkMfaKeyPrefix(
		options.keyPrefix ?? DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX,
		"MfaTransactionStore (redis)",
	);
	const logger = options.logger ?? consoleLogger;
	const txKey = (id: string): string => `${keyPrefix}tx:{${mfaKeyPart(id)}}`;
	const indexKey = (digest: string): string => `${keyPrefix}binding:{${digest}}`;
	/** A transaction's member in its binding's index. */
	const memberOf = (incarnation: string, id: string): string => `${incarnation}:${mfaKeyPart(id)}`;
	/**
	 * Takes a transaction already gone out of its binding's index. Best
	 * effort: the operation that removed it has answered, and must keep its
	 * answer. A member that fails to leave is warned, and counts for a
	 * transaction that is gone until its `expiresAtMs`: it scores late, so it
	 * is not taken out first, and meanwhile a create past the cap may end a
	 * live transaction early. Its own eviction deletes nothing (the
	 * incarnation is gone).
	 */
	const unindex = async (
		removed: Partial<MfaRemovedTransaction>,
		id: string,
		operation: "consume" | "reserveAttempt",
	): Promise<void> => {
		const { index, incarnation } = removed;
		if (index === undefined || incarnation === undefined) return;
		if (!isKeyText(index) || !isKeyText(incarnation)) return;
		await client
			.unindexTransaction(indexKey(index), memberOf(incarnation, id))
			.catch((err: unknown) =>
				logger.warn({ operation, err: loggableError(err) }, "mfa_transaction_unindex_failed"),
			);
	};
	/**
	 * Ends a transaction its binding's index took out, while it holds the
	 * incarnation the member names. Best effort: the create that took it out
	 * has written and indexed its own transaction, and a failed eviction must
	 * not turn that working ceremony into an outage. It is warned, and the
	 * transaction not ended stays, one past the cap, until it expires.
	 */
	const evict = async (member: string): Promise<void> => {
		const at = member.indexOf(":");
		const incarnation = member.slice(0, at);
		const part = member.slice(at + 1);
		if (at < 0 || !isKeyText(incarnation) || !isKeyText(part)) return;
		await client
			.evictTransaction(`${keyPrefix}tx:{${part}}`, incarnation)
			.catch((err: unknown) =>
				logger.warn({ err: loggableError(err) }, "mfa_transaction_evict_failed"),
			);
	};
	const subjectKeys = (subject: string): MfaSubjectKeys => {
		const tag = `{${mfaKeyPart(subject)}}`;
		return {
			lock: `${keyPrefix}lock:${tag}`,
			week: `${keyPrefix}week:${tag}`,
			recovery: `${keyPrefix}recovery:${tag}`,
			lease: `${keyPrefix}lease:${tag}`,
		};
	};
	const proofKey = (subject: string): string => `${keyPrefix}proof:{${mfaKeyPart(subject)}}`;
	const sessionProofKey = (subject: string, sid: string): string =>
		`${keyPrefix}session-proof:{${mfaKeyPart(subject)}}:${mfaKeyPart(sid)}`;
	const firstBindingKey = (subject: string): string =>
		`${keyPrefix}first-binding:{${mfaKeyPart(subject)}}`;

	return {
		kind: "redis",

		async create(tx) {
			const record = newMfaTransactionRecord(tx);
			if (!isStorableExpiry(record.expiresAtMs) || record.expiresAtMs <= clock()) {
				throw new RangeError(
					"MfaTransactionStore.create: expiresAtMs must be a future instant within the Date range",
				);
			}
			const incarnation = randomBytes(16).toString("base64url");
			const written = await client.create(
				txKey(record.id),
				fieldsOf(record, incarnation, bindingDigest(record.binding)),
				Math.ceil(record.expiresAtMs),
			);
			if (!written) throw new Error("an MFA transaction with this id already exists");
			const ended = await client.indexTransaction(
				indexKey(bindingDigest(record.binding)),
				memberOf(incarnation, record.id),
				record.expiresAtMs,
				MFA_MAX_TRANSACTIONS_PER_BINDING,
			);
			await Promise.all(ended.map(evict));
		},

		async get(id) {
			return transactionOf(await client.read(txKey(id)), id, clock());
		},

		async update(id, expectedVersion, patch) {
			const writes = mfaTransactionPatchWrites(patch);
			// Refused before the read: HINCRBY past it would write 2^53, which
			// `transactionOf` refuses, leaving the transaction unreadable.
			checkMfaVersionAdvances(expectedVersion, "MfaTransactionStore.update");
			const key = txKey(id);
			const fields = await client.read(key);
			const current = transactionOf(fields, id, clock());
			if (current === null || current.version !== expectedVersion) return null;
			checkMfaTransactionTransitions(current, writes);
			const set: Record<string, string> = {};
			const clear: string[] = [];
			for (const [field, value] of writes) {
				if (value === undefined) clear.push(field);
				else set[field] = PATCH_FIELD_TEXT[field](value);
			}
			const written = await client.update(key, {
				expectedVersion: String(expectedVersion),
				incarnation: fields.incarnation ?? "",
				set,
				clear,
			});
			return written === null ? null : transactionOf(written, id, clock());
		},

		async reserveAttempt(id, max) {
			if (!Number.isSafeInteger(max) || max <= 0) {
				throw new RangeError(
					"MfaTransactionStore.reserveAttempt: max must be a positive whole number",
				);
			}
			const { ok, attempts, removed } = await client.reserveAttempt(txKey(id), max, clock());
			if (removed !== undefined) await unindex(removed, id, "reserveAttempt");
			return { ok, attempts };
		},

		async takeChallenge(id, expectedVersion) {
			if (!isWholeVersion(expectedVersion)) return null;
			return challengeOf(await client.takeChallenge(txKey(id), String(expectedVersion), clock()));
		},

		async consume(id, expectedVersion) {
			if (!isWholeVersion(expectedVersion)) return null;
			const fields = await client.consume(txKey(id), String(expectedVersion));
			if (fields === null) return null;
			await unindex(fields, id, "consume");
			return transactionOf(fields, id, clock());
		},

		async reserveSubjectAttempt(subject, nowMs, policy) {
			// One read of the policy: the values it checks are the values the script applies.
			const checked = checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "reserveSubjectAttempt");
			const reservation = randomBytes(16).toString("base64url");
			const reply = await client.reserveSubjectAttempt(subjectKeys(subject), {
				nowMs,
				policy: checked,
				reservation,
			});
			return reply.ok
				? { ok: true, reservation }
				: { ok: false, hold: reply.hold, retryAfterMs: reply.retryAfterMs, first: reply.first };
		},

		async settleSubjectAttempt(subject, reservation, outcome) {
			if (outcome !== "failure" && outcome !== "success" && outcome !== "void") {
				throw new RangeError(
					"MfaTransactionStore.settleSubjectAttempt: outcome must be failure, success or void",
				);
			}
			await client.settleSubjectAttempt(subjectKeys(subject), reservation, outcome);
		},

		async noteExemptSuccess(subject, nowMs, policy) {
			const checked = checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "noteExemptSuccess");
			await client.noteExemptSuccess(subjectKeys(subject), { nowMs, policy: checked });
		},

		async requireEmailProofAtNextBinding(subject) {
			await client.requireEmailProof(proofKey(subject));
		},

		async emailProofRequiredAtNextBinding(subject) {
			return client.emailProofRequired(proofKey(subject));
		},

		async consumeEmailProofRequirement(subject) {
			return client.consumeEmailProof(proofKey(subject));
		},

		async recordSessionEmailProof(subject, sid, provedAtMs, untilMs) {
			const nowMs = clock();
			checkSessionEmailProof(subject, sid, provedAtMs, untilMs, nowMs);
			await client.recordSessionEmailProof(
				sessionProofKey(subject, sid),
				JSON.stringify({ provedAtMs, untilMs }),
				Math.ceil(untilMs - nowMs),
			);
		},

		async sessionEmailProofAt(subject, sid, nowMs) {
			checkSessionEmailProofQuestion(subject, sid, nowMs);
			const text = await client.sessionEmailProof(sessionProofKey(subject, sid));
			const storeNowMs = clock();
			const proof = sessionProofOf(text, subject, sid, storeNowMs);
			return proof === null ? null : sessionEmailProofAnswer(proof, nowMs, storeNowMs);
		},

		async noteFirstBinding(subject, atMs, untilMs) {
			// The shape here; the clock's bounds in the script, on the server's clock.
			checkFirstBindingNote(subject, atMs, untilMs);
			const reply = await client.noteFirstBinding(firstBindingKey(subject), {
				atMs,
				untilMs,
				skewMs: DEFAULT_CLOCK_SKEW_MS,
				longestMs: MFA_CLOCK_SKEW_ALLOWANCE_MS,
			});
			if (reply.noted) return;
			checkFirstBindingNote(subject, atMs, untilMs, reply.serverNowMs);
			throw new RangeError(
				"MfaTransactionStore.noteFirstBinding: the mark does not stand on the store's clock",
			);
		},

		async firstBindingAt(subject, nowMs) {
			checkFirstBindingQuestion(subject, nowMs);
			const { value, serverNowMs } = await client.firstBindingMark(firstBindingKey(subject));
			const mark = firstBindingMarkOf(value, subject);
			return mark === null ? null : firstBindingAnswer(mark, serverNowMs);
		},

		async subjectGeneration(subject) {
			checkSubjectQuestion("subjectGeneration", subject);
			return countIn(await client.subjectGeneration(subjectKeys(subject)), "subject generation");
		},

		async acquireSubjectLease(subject, request) {
			const { ttlMs, generation } = checkSubjectLeaseRequest(subject, request);
			const token = randomBytes(16).toString("base64url");
			const reply = await client.acquireSubjectLease(subjectKeys(subject), {
				token,
				ttlMs,
				generation,
			});
			return reply.outcome === "acquired" ? { outcome: "acquired", token } : reply;
		},

		async releaseSubjectLease(subject, token) {
			checkSubjectLeaseRelease(subject, token);
			return client.releaseSubjectLease(subjectKeys(subject), token);
		},

		async raiseRecoverySetFloor(subject, raise) {
			const checked = checkRecoverySetFloorRaise(subject, raise);
			const reply = await client.raiseRecoverySetFloor(subjectKeys(subject), checked);
			return reply.raised
				? { outcome: "raised", floor: countIn(reply.floor, "recovery-set floor") }
				: { outcome: "refused", reason: "lease_not_held" };
		},

		async recoverySetFloor(subject) {
			checkSubjectQuestion("recoverySetFloor", subject);
			return countIn(await client.recoverySetFloor(subjectKeys(subject)), "recovery-set floor");
		},

		async authorizeSubjectRecovery(subject, authorization) {
			// The shape here; the clock's bounds in the script, on the server's clock.
			const checked = checkSubjectRecoveryAuthorization(subject, authorization);
			const reply = await client.authorizeSubjectRecovery(subjectKeys(subject), {
				field: recoveryField(checked.operation, checked.sid),
				recoveryId: checked.recoveryId,
				expiresAtMs: checked.expiresAtMs,
				maxAheadMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS + DEFAULT_CLOCK_SKEW_MS,
			});
			if (reply.authorized) return;
			checkSubjectRecoveryAuthorization(subject, authorization, reply.serverNowMs);
			throw new RangeError(
				"MfaTransactionStore.authorizeSubjectRecovery: the authorization does not stand on the store's clock",
			);
		},

		async applySubjectRecovery(subject, application) {
			const checked = checkSubjectRecoveryApplication(subject, application);
			const reply = await client.applySubjectRecovery(subjectKeys(subject), {
				operation: checked.operation,
				field: recoveryField(checked.operation, checked.sid),
				nowMs: checked.nowMs,
				leaseToken: checked.leaseToken,
				sessionsBoundaryMs: checked.sessionsBoundaryMs,
				guessableBoundSinceMs: checked.guessableBoundSinceMs,
				clockSkewMs: DEFAULT_CLOCK_SKEW_MS,
			});
			const answer = readMfaSubjectRecoveryAnswer(recoveryAnswerOf(reply));
			if (answer === undefined) {
				throw new Error("MfaTransactionStore: the apply script answered nothing it knows");
			}
			return answer;
		},
	};
}

// --- the module ------------------------------------------------------------

/**
 * `defineModule` manifest for the Redis {@link MfaTransactionStore}, off the
 * `mfaTransactionStoreClient` slot, keys under
 * `redis-mfa-transaction-store.keyPrefix` (`mfat:`), its own section (strict).
 * Declares no `replicaSafety`:
 * transactions, attempt limits and the lock are shared by every replica.
 *
 * The email-proof requirement must last as enrolled factors do, so before
 * providing the store it runs the factor store's durability check: an
 * `allkeys-*` eviction policy refuses the boot (`mfa-transaction-store-evictable`);
 * RDB without AOF (`mfa_transaction_store_lossy`), no persistence
 * (`mfa_transaction_store_volatile`) and a server refusing `CONFIG`
 * (`mfa_transaction_store_durability_unchecked`) each warn on the `logger` slot
 * (or `consoleLogger`). So does a `volatile-*` policy
 * (`mfa_transaction_store_lock_evictable`, naming `evictableFamilies`): the
 * lock state carries a TTL once no run is counted, and evicting it lifts a
 * lockout hold early; a first-binding mark carries one always, and evicting
 * it fails open — a stale session's first binding is no longer refused; a
 * subject's lease carries one always, and evicting it lets a second writer
 * at the subject's factor set.
 */
export const redisMfaTransactionStoreModule = defineModule({
	name: "redis-mfa-transaction-store",
	section: {
		schema: keyPrefixSection(DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX),
		reference: redisReference(),
		relocatedFrom: {
			redisMfaTransactionStore: { to: "", environmentVariable: null },
			"redisMfaTransactionStore.keyPrefix": "keyPrefix",
		},
	},
	requires: ["mfaTransactionStoreClient"] as const,
	optional: ["logger"] as const,
	provides: {
		mfaTransactionStore: async (deps) => {
			// Built first, so a prefix it refuses is refused before the server is asked.
			const store = createRedisMfaTransactionStore({
				client: deps.mfaTransactionStoreClient,
				keyPrefix: deps.section.keyPrefix,
				logger: deps.logger ?? consoleLogger,
			});
			await checkRedisMfaStoreDurability(
				"mfaTransactionStore",
				() => deps.mfaTransactionStoreClient.durability(),
				deps.logger ?? consoleLogger,
			);
			return store;
		},
	},
});
