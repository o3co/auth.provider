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
 * subject's lock state and the email-proof requirement; and the durability report both are
 * checked by at boot.
 */

import type {
	MfaLockoutPolicy,
	MfaSubjectAttemptOutcome,
	MfaSubjectHold,
} from "@o3co/auth-provider-core";

// --- MfaFactorStoreClient --------------------------------------------------

/**
 * What a Redis server says about keeping what it is written — read at boot
 * by the two MFA store modules (ADR 2026-09-25-multi-factor-authentication,
 * D12). Each part is `undefined` when it could not be read: the server
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
 * 2026-09-25-multi-factor-authentication, D7): one hash per subject, a field
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
 * A subject's lock-state keys. Both carry the subject's hash tag: every
 * operation on the state is one script over the two.
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
}

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
	/** The time of the exempt success: the attempts up to it are counted, and end below the hard limit. */
	readonly nowMs: number;
	/** The lockout policy; a run at or past its `hardLimit` up to `nowMs` stands. */
	readonly policy: MfaLockoutPolicy;
}

/**
 * Backing client for the `MfaTransactionStore` adapter (ADR
 * 2026-09-25-multi-factor-authentication, D8, D21, D25).
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
	/** Remove both keys. */
	clearSubjectState(keys: MfaSubjectKeys): Promise<void>;
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
	/** As `MfaFactorStoreClient.durability`: the requirement must be kept as the factors are. */
	durability(): Promise<RedisDurability>;
}
