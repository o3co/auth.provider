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
 * The MFA stores' clients: the enrolled factors, one hash per subject; the transactions, a
 * subject's lock state, the email-proof requirement, a session's proof and a subject's
 * first-binding mark; and the durability report both are checked by at boot.
 */

import type {
	MfaLockoutPolicy,
	MfaSubjectAttemptOutcome,
	MfaSubjectHold,
	MfaSubjectRecoveryOperation,
} from "@o3co/auth-provider-core";

// --- MfaFactorStoreClient --------------------------------------------------

/**
 * What a Redis server says about keeping what it is written — read at boot
 * by the two MFA store modules (ADR 2026-09-25-multi-factor-authentication,
 * on durability). Each part is `undefined` when it could not be read: the server
 * refused the question (`refusal`), or answered without the value.
 */
export interface RedisDurability {
	/** `INFO memory`'s `maxmemory_policy`, or `CONFIG GET maxmemory-policy` where INFO does not say. */
	readonly maxmemoryPolicy: string | undefined;
	/** `INFO persistence`'s `aof_enabled`. */
	readonly appendOnly: boolean | undefined;
	/** `CONFIG GET save` is not empty: RDB snapshots are taken. Asked only when AOF is off. */
	readonly snapshots: boolean | undefined;
	/** The first reply that refused a question — an unknown or renamed command, `NOPERM`, a disabled command — as the driver raised it. Logged by its projection only. */
	readonly refusal: unknown;
}

/**
 * What an update writes over a factor record's version and its mutable part,
 * each as the text the record keeps.
 */
export interface MfaFactorRecordUpdateInput {
	/** The version the record must still be at, as decimal text. */
	readonly expectedVersion: string;
	/** The version it is at afterwards, as decimal text. */
	readonly nextVersion: string;
	/** The new mutable part: one line of JSON. */
	readonly mutable: string;
}

/**
 * Backing client for the `MfaFactorStore` adapter (ADR
 * 2026-09-25-multi-factor-authentication): one hash per subject, a field
 * per factor.
 *
 * A factor's value is three lines — `<version>\n<fixed>\n<mutable>` — where
 * `<version>` is decimal text and `<fixed>` and `<mutable>` are one line of
 * JSON each (`JSON.stringify` never writes a raw line feed). The split lets
 * `update` be one indivisible step that never decodes the JSON: it compares
 * the version as text, keeps the fixed part byte for byte, and writes the
 * new version and mutable part beside it. A script that decoded and
 * re-encoded the record would change it (`cjson` writes an empty array as
 * `{}`), so none does. Every operation touches the one key it is handed, so
 * this client needs no hash tag to run on Cluster.
 */
export interface MfaFactorStoreClient {
	/** Every field of the hash at `key` and its value (`HGETALL`); `{}` when there is none. */
	list(key: string): Promise<Readonly<Record<string, string>>>;
	/** Write `value` under `field` only while the field is absent (`HSETNX`). Resolves whether it wrote. */
	create(key: string, field: string, value: string): Promise<boolean>;
	/**
	 * Atomically: while the value under `field` is at `input.expectedVersion`,
	 * replace its version and mutable part, keep its fixed part, and resolve
	 * the value as written; `null` when the field is absent, at another
	 * version, or not three lines.
	 */
	update(key: string, field: string, input: MfaFactorRecordUpdateInput): Promise<string | null>;
	/** Remove `field` (`HDEL`). Idempotent. */
	remove(key: string, field: string): Promise<void>;
	/** Remove the whole hash (`DEL`). Idempotent. */
	removeAll(key: string): Promise<void>;
	/**
	 * What the server says about keeping what it is written. A reply
	 * that refuses a question leaves that part unread; any other reply error,
	 * and a server that cannot be asked at all, rejects.
	 */
	durability(): Promise<RedisDurability>;
}

// --- MfaTransactionStoreClient --------------------------------------------

/** What an update writes, as the transaction's hash keeps it. */
export interface MfaTransactionUpdateInput {
	/** The version the transaction must still be at, as decimal text. */
	readonly expectedVersion: string;
	/**
	 * The value its `incarnation` field must still hold: the random value
	 * `create` wrote, so a transaction consumed and created again under the
	 * same id, at the same version, is never written with a patch that was
	 * checked against the one before it.
	 */
	readonly incarnation: string;
	/** Fields to write, and the text each is written as. */
	readonly set: Readonly<Record<string, string>>;
	/** Fields to remove. */
	readonly clear: readonly string[];
}

/**
 * A subject's keys. Each carries the subject's hash tag: every operation on
 * them is one command or one script on one Cluster slot.
 */
export interface MfaSubjectKeys {
	/**
	 * HASH: `seq`, the order counter; `r:<id>` → `<seq>|<atMs>` for each
	 * attempt in the consecutive run; `p:<id>` → `<seq>` for each reservation
	 * not yet settled; `held` → `1` while an episode of refusals is under way.
	 * A field of any other kind is ignored.
	 */
	readonly lock: string;
	/** ZSET: the attempts the rolling week counts, each scored by its time. */
	readonly week: string;
	/**
	 * HASH: `g`, the subject's generation, and `floor`, its recovery-set floor,
	 * each as decimal text (absent is `0`);
	 * `a:<operation>:<sid>` → `p|<expiresAtMs>|<recoveryId>` for each
	 * authorization pending, `a|<generation>|<expiresAtMs>|<recoveryId>` once applied.
	 */
	readonly recovery: string;
	/** STRING: the lease holder's token, expiring at the lease's end on the server's clock. */
	readonly lease: string;
}

export interface AcquireMfaSubjectLeaseInput {
	/** The token the lease is written with when it is free. */
	readonly token: string;
	readonly ttlMs: number;
	/** The generation the writer captured. */
	readonly generation: number;
}

export interface AuthorizeMfaSubjectRecoveryInput {
	/** The recovery hash's field for the authorization's operation and sid. */
	readonly field: string;
	readonly recoveryId: string;
	readonly expiresAtMs: number;
	/** How far ahead of the server's clock its end may lie. */
	readonly maxAheadMs: number;
}

/** What an authorize answers: written, or refused on the server's clock, which it names. */
export type AuthorizeMfaSubjectRecoveryReply =
	| { readonly authorized: true }
	| { readonly authorized: false; readonly serverNowMs: number };

export interface RaiseMfaRecoverySetFloorInput {
	/** A recovery-code set's generation, not the subject's. */
	readonly setGeneration: number;
	readonly leaseToken: string;
}

/** What a floor raise answers: the floor after it, as the hash keeps it, or nothing raised without the lease. */
export type RaiseMfaRecoverySetFloorReply =
	| { readonly raised: true; readonly floor: string }
	| { readonly raised: false };

export interface ApplyMfaSubjectRecoveryInput {
	readonly operation: MfaSubjectRecoveryOperation;
	/** The recovery hash's field for the operation and sid. */
	readonly field: string;
	readonly nowMs: number;
	readonly leaseToken: string;
	readonly sessionsBoundaryMs: number | undefined;
	/** A recover's earliest guessable record's time, or `null` when none remains; a reset's `undefined`. */
	readonly guessableBoundSinceMs: number | null | undefined;
	/** The clock skew allowed between the caller's times (`DEFAULT_CLOCK_SKEW_MS`). */
	readonly clockSkewMs: number;
}

/**
 * What the apply script answers, each part as its text: `refused, reason, hard`;
 * `already, recoveryId, generation, hard`; or
 * `applied, recoveryId, generation, week, run, liftedHard, hard`, each flag `1` or `0`. The
 * adapter reads it into the port's answer.
 */
export type ApplyMfaSubjectRecoveryReply = readonly string[];

/** What an acquire answers, as the port's `acquireSubjectLease` but for the token, which the caller made. */
export type AcquireMfaSubjectLeaseReply =
	| { readonly outcome: "acquired" }
	| { readonly outcome: "busy"; readonly retryAfterMs: number }
	| { readonly outcome: "stale" };

export interface ReserveMfaSubjectAttemptInput {
	/** The caller's time, which every hold is judged on. */
	readonly nowMs: number;
	readonly policy: MfaLockoutPolicy;
	/** The id the attempt is recorded under when it is let through. */
	readonly reservation: string;
}

export type ReserveMfaSubjectAttemptReply =
	| { readonly ok: true }
	| {
			readonly ok: false;
			readonly hold: MfaSubjectHold;
			/** Milliseconds from `nowMs` until an attempt may be reserved; `null` for the hard hold. */
			readonly retryAfterMs: number | null;
			/** Whether this refusal begins an episode, as the port's `first`. */
			readonly first: boolean;
	  };

export interface NoteMfaExemptSuccessInput {
	/** The time of the exempt success: before the hard hold is fixed, the attempts up to it end. */
	readonly nowMs: number;
	/** The lockout policy; a run already at or past its `hardLimit` fixes the hard hold instead. */
	readonly policy: MfaLockoutPolicy;
}

/** A subject's first-binding mark to note; the server's clock judges it. */
export interface NoteMfaFirstBindingInput {
	readonly atMs: number;
	readonly untilMs: number;
	/** How far either side of the server's clock a mark's time may lie (`DEFAULT_CLOCK_SKEW_MS`). */
	readonly skewMs: number;
	/** The longest a held mark may stand past its time and still be one (`MFA_CLOCK_SKEW_ALLOWANCE_MS`). */
	readonly longestMs: number;
}

/** What a note answers: kept, or refused on the server's clock, which it names. */
export type NoteMfaFirstBindingReply =
	| { readonly noted: true }
	| { readonly noted: false; readonly serverNowMs: number };

/** A subject's first-binding mark as read, with the server's clock at the read. */
export interface MfaFirstBindingRead {
	/** The key's value; `null` when there is none. */
	readonly value: string | null;
	readonly serverNowMs: number;
}

/**
 * Backing client for the `MfaTransactionStore` adapter (ADR
 * 2026-09-25-multi-factor-authentication): the transactions, the subject
 * lock state and its recovery, the lease, the email-proof requirement, a
 * session's proof and a subject's first-binding mark.
 *
 * Semantic operations: every one the port calls atomic is a read, a decision
 * and a write, which Redis makes one step only as a script (see
 * `makeIoredisClients`). The operations here read a transaction's `version`,
 * `incarnation`, `attempts`, `challenge` and `expiresAtMs` fields by name,
 * and never decode its `record`.
 *
 * The subject state's decisions — backoff, weekly budget and hard limit —
 * are the port's rules, judged on the caller's `nowMs`;
 * what is reclaimed is judged on the server's clock, never later than a day
 * after it stops counting (`MFA_CLOCK_SKEW_ALLOWANCE_MS`). A stored value an
 * operation cannot read is refused with an error, never read as a state that
 * holds nothing.
 */
export interface MfaTransactionStoreClient {
	/**
	 * Write the transaction's `fields` into the hash at `key`, and its deadline
	 * (`PEXPIREAT deadlineMs`), only while no live one is there. Resolves
	 * whether it wrote.
	 */
	create(
		key: string,
		fields: Readonly<Record<string, string>>,
		deadlineMs: number,
	): Promise<boolean>;
	/** Every field of the hash at `key` (`HGETALL`); `{}` when there is none. */
	read(key: string): Promise<Readonly<Record<string, string>>>;
	/**
	 * Atomically: while the transaction is at `expectedVersion` and its
	 * incarnation, write `set`, remove `clear`, add one to `version`, and
	 * resolve every field as written; `null` otherwise. The deadline stays.
	 */
	update(
		key: string,
		input: MfaTransactionUpdateInput,
	): Promise<Readonly<Record<string, string>> | null>;
	/**
	 * Atomically: `attempts` + 1 while that is within `max`; past it — or on
	 * a count that is not a number — the transaction is deleted and the
	 * attempts it had are answered with `ok: false`. No transaction, or one
	 * gone at `nowMs` — at or past the deadline its `expiresAtMs` field holds
	 * as decimal text, or holding none that is a finite number — is
	 * `{ ok: false, attempts: 0 }`, spending nothing: the store's clock is the
	 * transaction's, whatever the server's says, and the key is left to its
	 * deadline on the server's.
	 */
	reserveAttempt(
		key: string,
		max: number,
		nowMs: number,
	): Promise<{ readonly ok: boolean; readonly attempts: number }>;
	/**
	 * Atomically: the `challenge` field, removed, while the version is
	 * `expectedVersion` and the transaction is not gone at `nowMs` (as
	 * `reserveAttempt` judges it); `null` otherwise, taking nothing.
	 */
	takeChallenge(key: string, expectedVersion: string, nowMs: number): Promise<string | null>;
	/** Atomically: every field, and the hash deleted, while the version is `expectedVersion`; `null` otherwise. */
	consume(key: string, expectedVersion: string): Promise<Readonly<Record<string, string>> | null>;
	/** The port's `reserveSubjectAttempt`, one script over both keys. */
	reserveSubjectAttempt(
		keys: MfaSubjectKeys,
		input: ReserveMfaSubjectAttemptInput,
	): Promise<ReserveMfaSubjectAttemptReply>;
	/** The port's `settleSubjectAttempt`, one script over both keys; a reservation not in flight changes nothing. */
	settleSubjectAttempt(
		keys: MfaSubjectKeys,
		reservation: string,
		outcome: MfaSubjectAttemptOutcome,
	): Promise<void>;
	/** The port's `noteExemptSuccess`, one script over both keys. */
	noteExemptSuccess(keys: MfaSubjectKeys, input: NoteMfaExemptSuccessInput): Promise<void>;
	/** Record the email-proof requirement at `key`, with no TTL. Idempotent. */
	requireEmailProof(key: string): Promise<void>;
	/** Whether the requirement is recorded at `key`. */
	emailProofRequired(key: string): Promise<boolean>;
	/** Remove the requirement at `key` (`DEL`); resolves whether this call removed it. */
	consumeEmailProof(key: string): Promise<boolean>;
	/** Write a session's email proof `value` at `key`, replacing any, expiring `ttlMs` from when the server takes it (`SET … PX`). */
	recordSessionEmailProof(key: string, value: string, ttlMs: number): Promise<void>;
	/** The session's email proof at `key` (`GET`); `null` when there is none. */
	sessionEmailProof(key: string): Promise<string | null>;
	/**
	 * Atomically, on the server's clock: refuse a mark whose `untilMs` is not after it or
	 * whose `atMs` lies further from it than `input.skewMs`, writing nothing; otherwise write
	 * the later `atMs` and the later `untilMs` of the mark held, while it stands, and this
	 * one, expiring at that `untilMs` (`SET … PXAT`). A held mark is judged on its shape
	 * alone, never on where its time sits on the server's clock; a held value that is not a
	 * mark (`input.longestMs` bounding how long one stands), or a key of another type, is
	 * replaced.
	 */
	noteFirstBinding(key: string, input: NoteMfaFirstBindingInput): Promise<NoteMfaFirstBindingReply>;
	/** The subject's first-binding mark at `key`, and the server's clock, in one step. */
	firstBindingMark(key: string): Promise<MfaFirstBindingRead>;
	/** The recovery hash's `g` field (`HGET`); `null` when there is none. */
	subjectGeneration(keys: MfaSubjectKeys): Promise<string | null>;
	/**
	 * Atomically: `stale` when `input.generation` is not the recovery hash's `g`
	 * (absent is `0`); else `busy`, with the lease's time left, while one stands; else the lease
	 * written with `input.token` for `input.ttlMs` (`SET NX PX`).
	 */
	acquireSubjectLease(
		keys: MfaSubjectKeys,
		input: AcquireMfaSubjectLeaseInput,
	): Promise<AcquireMfaSubjectLeaseReply>;
	/** Atomically: delete the lease while it holds `token`; resolves whether it did. One at its last millisecond has lapsed (`false`); one holding it with no deadline rejects, nothing deleted. */
	releaseSubjectLease(keys: MfaSubjectKeys, token: string): Promise<boolean>;
	/**
	 * Atomically, on the server's clock: refuse an authorization whose end is not after it or
	 * lies further ahead than `input.maxAheadMs`, writing nothing; otherwise drop the
	 * authorizations ended on it and write this one, pending, over whatever its field held.
	 */
	authorizeSubjectRecovery(
		keys: MfaSubjectKeys,
		input: AuthorizeMfaSubjectRecoveryInput,
	): Promise<AuthorizeMfaSubjectRecoveryReply>;
	/** The recovery hash's `floor` field (`HGET`); `null` when there is none. */
	recoverySetFloor(keys: MfaSubjectKeys): Promise<string | null>;
	/**
	 * Atomically, while the lease holds `input.leaseToken`: raise the recovery hash's `floor` to
	 * `input.setGeneration` — a recovery-code set's generation, not the subject's — when it is
	 * higher, and resolve the floor after, as decimal text; otherwise write nothing.
	 */
	raiseRecoverySetFloor(
		keys: MfaSubjectKeys,
		input: RaiseMfaRecoverySetFloorInput,
	): Promise<RaiseMfaRecoverySetFloorReply>;
	/** The port's `applySubjectRecovery`, one script over the four keys, its reply as text; one that is not a list of text rejects. */
	applySubjectRecovery(
		keys: MfaSubjectKeys,
		input: ApplyMfaSubjectRecoveryInput,
	): Promise<ApplyMfaSubjectRecoveryReply>;
	/** As `MfaFactorStoreClient.durability`: the requirement must be kept as the factors are. */
	durability(): Promise<RedisDurability>;
}
