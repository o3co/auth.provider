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
 * Redis {@link MfaTransactionStore} (the MFA ADR's D8, D21, D25): the
 * single-use record of each second-factor ceremony, the subject lock that
 * bounds guessable proofs, and the email proof an operator reset requires.
 *
 * ```text
 * <keyPrefix>tx:{<id>}          HASH   one transaction, expiring at its expiresAtMs
 * <keyPrefix>lock:{<subject>}   HASH   D21's run, reservations in flight and trusted browsers
 * <keyPrefix>week:{<subject>}   ZSET   the weekly window: one member per attempt, scored by its time
 * <keyPrefix>proof:{<subject>}  STRING the email-proof requirement (D25), with no TTL
 * ```
 *
 * `<id>` and `<subject>` are base64url of their JSON (`internal/mfa-keys.mts`).
 * A subject's lock hash and its week share the subject's hash tag, so each
 * operation on the state is one script on one Cluster slot; a transaction is
 * one key, and so is the requirement.
 *
 * **Every operation a race could split is one script** (`makeIoredisClients`
 * holds them): create is insert-only, update a compare-and-set on the version,
 * `reserveAttempt` spends an attempt before a proof is checked, `takeChallenge`
 * answers a challenge once, `consume` gives the transaction to one
 * verification, and each of D21's operations reads, decides and writes the
 * subject state in one step. The requirement is one command each way.
 *
 * **What a transaction is.** Core defines it and this adapter reads it back
 * through core: `create` keeps what `newMfaTransactionRecord` answers, and a
 * read rebuilds the record through the same function, so what comes back has
 * the shape and the rules the in-process store's has. The continuation's
 * instants are epoch milliseconds (the session-admission ADR's D5) and the
 * record travels as JSON, as the session envelope's claims and the cookie
 * session's `user` do. A transaction that does not read back is answered as
 * absent: the ceremony fails closed — the user starts again — where an outage
 * would answer 503 for the rest of its ten minutes.
 *
 * **Two clocks.** A transaction expires on the server's clock, at its
 * `expiresAtMs` rounded up to a whole millisecond (`PEXPIREAT`), and `create`
 * refuses one already past on this process's. D21's answers are judged on the
 * time the caller passes; what the scripts forget and what Redis reclaims is
 * judged no later than the server's clock, less a day
 * (`MFA_CLOCK_SKEW_ALLOWANCE_MS`). While a run is counted the subject's keys
 * carry no TTL — only a success, an exempt success or `clearSubjectState`
 * ends it — and a subject state a script cannot read is refused, never read as
 * one that holds nothing.
 *
 * **Durability.** The requirement must be kept as the factor store is (D12's
 * step-3 amendment): it has no TTL, and `redisMfaTransactionStoreModule` holds
 * the server to the factor store's boot check.
 */

import { createHash, randomBytes } from "node:crypto";
import {
	checkMfaLockoutPolicy,
	checkMfaTransactionTransitions,
	isStorableExpiry,
	type MfaTransaction,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	mfaTransactionPatchWrites,
	newMfaTransactionRecord,
} from "@o3co/auth-provider-core";
import type { MfaSubjectKeys, MfaTransactionStoreClient } from "./clients.mjs";
import { checkMfaKeyPrefix, mfaKeyPart } from "./internal/mfa-keys.mjs";

/** The key namespace `redisMfaTransactionStore.keyPrefix` defaults to. */
export const DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX = "mfat:";

export interface RedisMfaTransactionStoreOptions {
	readonly client: MfaTransactionStoreClient;
	/** Outer namespace; each key's family and hash tag follow it. Without a brace. Default `mfat:`. */
	readonly keyPrefix?: string;
}

/** How each patch field is written into the hash. */
const PATCH_FIELD_TEXT: Readonly<Record<keyof MfaTransactionPatch, (value: unknown) => string>> = {
	enrollment: (value) => value as string,
	emailProof: (value) => JSON.stringify(value),
	challenge: (value) => JSON.stringify(value),
	pendingEnrollment: (value) => JSON.stringify(value),
	sends: (value) => String(value),
	lastSentAtMs: (value) => JSON.stringify(value),
};

/** The fields of a new transaction's hash. */
function fieldsOf(record: MfaTransaction, incarnation: string): Record<string, string> {
	const fields: Record<string, string> = {
		id: record.id,
		incarnation,
		version: String(record.version),
		attempts: "0",
		sends: String(record.sends),
		enrollment: record.enrollment,
		emailProof: JSON.stringify(record.emailProof),
		// What never changes after `create`, as one JSON document; absent is null.
		record: JSON.stringify({
			purpose: record.purpose,
			sessionId: record.sessionId,
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
	if (record.lastSentAtMs !== undefined) fields.lastSentAtMs = JSON.stringify(record.lastSentAtMs);
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
 * the in-process store keeps it — every field named, sub-objects to their
 * known fields, plain data — or `null` when they hold nothing, hold another
 * id's, or hold what that function refuses.
 */
function transactionOf(
	fields: Readonly<Record<string, string>>,
	id: string,
): MfaTransaction | null {
	if (fields.id !== id) return null;
	try {
		const fixed = parsed(fields.record);
		const attempts = countOf(fields.attempts);
		if (!isObject(fixed) || !Number.isSafeInteger(attempts)) return null;
		if (typeof fixed.expiresAtMs !== "number" || !Number.isFinite(fixed.expiresAtMs)) return null;
		const record = newMfaTransactionRecord({
			id,
			purpose: fixed.purpose,
			sessionId: fixed.sessionId,
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
			sends: countOf(fields.sends),
			lastSentAtMs: parsed(fields.lastSentAtMs),
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

const digestOf = (browser: string): string =>
	createHash("sha256").update(browser, "utf8").digest("base64url");

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
	const keyPrefix = checkMfaKeyPrefix(
		options.keyPrefix ?? DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX,
		"MfaTransactionStore (redis)",
	);
	const txKey = (id: string): string => `${keyPrefix}tx:{${mfaKeyPart(id)}}`;
	const subjectKeys = (subject: string): MfaSubjectKeys => {
		const tag = `{${mfaKeyPart(subject)}}`;
		return { lock: `${keyPrefix}lock:${tag}`, week: `${keyPrefix}week:${tag}` };
	};
	const proofKey = (subject: string): string => `${keyPrefix}proof:{${mfaKeyPart(subject)}}`;

	return {
		kind: "redis",

		async create(tx) {
			const record = newMfaTransactionRecord(tx);
			if (!isStorableExpiry(record.expiresAtMs) || record.expiresAtMs <= Date.now()) {
				throw new RangeError(
					"MfaTransactionStore.create: expiresAtMs must be a future instant within the Date range",
				);
			}
			const incarnation = randomBytes(16).toString("base64url");
			const written = await client.create(
				txKey(record.id),
				fieldsOf(record, incarnation),
				Math.ceil(record.expiresAtMs),
			);
			if (!written) throw new Error("an MFA transaction with this id already exists");
		},

		async get(id) {
			return transactionOf(await client.read(txKey(id)), id);
		},

		async update(id, expectedVersion, patch) {
			const writes = mfaTransactionPatchWrites(patch);
			const key = txKey(id);
			const fields = await client.read(key);
			const current = transactionOf(fields, id);
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
			return written === null ? null : transactionOf(written, id);
		},

		async reserveAttempt(id, max) {
			if (!Number.isSafeInteger(max) || max <= 0) {
				throw new RangeError(
					"MfaTransactionStore.reserveAttempt: max must be a positive whole number",
				);
			}
			return client.reserveAttempt(txKey(id), max);
		},

		async takeChallenge(id, expectedVersion) {
			if (!isWholeVersion(expectedVersion)) return null;
			return challengeOf(await client.takeChallenge(txKey(id), String(expectedVersion)));
		},

		async consume(id, expectedVersion) {
			if (!isWholeVersion(expectedVersion)) return null;
			const fields = await client.consume(txKey(id), String(expectedVersion));
			return fields === null ? null : transactionOf(fields, id);
		},

		async reserveSubjectAttempt(subject, nowMs, policy, browser) {
			checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "reserveSubjectAttempt");
			const reservation = randomBytes(16).toString("base64url");
			const reply = await client.reserveSubjectAttempt(subjectKeys(subject), {
				nowMs,
				policy,
				browserDigest: browser === undefined ? undefined : digestOf(browser),
				reservation,
			});
			return reply.ok
				? { ok: true, reservation }
				: { ok: false, hold: reply.hold, retryAfterMs: reply.retryAfterMs };
		},

		async settleSubjectAttempt(subject, reservation, outcome) {
			if (outcome !== "failure" && outcome !== "success" && outcome !== "void") {
				throw new RangeError(
					"MfaTransactionStore.settleSubjectAttempt: outcome must be failure, success or void",
				);
			}
			await client.settleSubjectAttempt(subjectKeys(subject), reservation, outcome);
		},

		async noteExemptSuccess(subject, nowMs, policy, presented) {
			checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "noteExemptSuccess");
			const browser = randomBytes(32).toString("base64url");
			await client.noteExemptSuccess(subjectKeys(subject), {
				nowMs,
				policy,
				presentedDigest: presented === undefined ? undefined : digestOf(presented),
				digest: digestOf(browser),
			});
			return { browser };
		},

		async clearSubjectState(subject) {
			// The email-proof requirement is not lock state: it stays.
			await client.clearSubjectState(subjectKeys(subject));
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
	};
}
