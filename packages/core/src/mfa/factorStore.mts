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
 * The enrolled-factor record, the port that keeps it, and its `mfaFactorStore`
 * slot (ADR 2026-09-25-multi-factor-authentication).
 *
 * A record's `data` is sealed by the coordinator and opaque to every store:
 * kept byte for byte, never decoded, logged or derived from. Only a subject
 * with no record that may count opens a first binding, so losing this store
 * is guarded separately by the enrollment witness on `UserRepository`.
 *
 * A subject's records are one set, and the store keeps one generation for
 * it: the factor set's store generation, a {@link StoreGeneration}. It is a
 * third thing beside two numeric generations of core's mfa module, and none
 * stands for another:
 *
 * - the subject's generation, on `MfaTransactionStore`: a count the subject's
 *   lease is acquired at, moved only by an applied recovery or reset;
 * - a recovery-code set's generation: a count kept inside that set's sealed
 *   `data`, which this store never reads;
 * - the factor set's store generation, here: an opaque value this store
 *   issues at every membership write, compared only with `===`. A
 *   conditional write names it as `expected`; an answer carries the new one
 *   as `generation`.
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import { lineSafeText } from "../logging/loggableError.mjs";
import { isHintToken } from "../session-admission/requirement.mjs";
// Stand-in for core's conditional-write convention until it lands; then these
// come from "../adapters/conditionalWrite.mjs".
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	readVersionedSet,
	type StoreGeneration,
	type VersionedSet,
} from "./conditionalWriteStandIn.mjs";

/** One second factor bound to one subject. Every field is a required key: a store that drops one does not compile. */
export interface MfaFactorRecord {
	/** 16 random bytes, base64url. Unique per subject. */
	readonly id: string;
	/** `User.id`. */
	readonly subject: string;
	/** `"totp"`, `"email"`, `"webauthn"`, `"recovery_code"`, or a contributed factor's kind. */
	readonly kind: string;
	/** What the user called it: at most 64 printable characters, checked by the coordinator. */
	readonly label: string | undefined;
	/**
	 * What authorized the binding: recorded for audit, not enforced.
	 * `password`: a password sign-in alone; `federated`: a federated sign-in
	 * alone, at the upstream IdP; `email_proof`: the account-email proof;
	 * `mfa`: recent MFA, beside another factor. A record written before the
	 * MFA package wrote `federated` may hold `password` for a federated
	 * binding: `password` alone does not prove a password was used.
	 */
	readonly binding: "password" | "email_proof" | "federated" | "mfa" | undefined;
	readonly createdAt: Date;
	readonly lastUsedAt: Date | undefined;
	/** Bumped by every update; the compare-and-set token. */
	readonly version: number;
	/** The factor's own state, sealed. Opaque to every store. */
	readonly data: string;
}

/** The most characters a factor's label holds. */
export const MFA_FACTOR_LABEL_MAX_LENGTH = 64;

const FACTOR_ID = /^[A-Za-z0-9_-]{22}$/;

/** Whether `value` is a factor id as the provider makes one: 16 random bytes, base64url, 22 characters. */
export const isMfaFactorId = (value: unknown): value is string =>
	typeof value === "string" && FACTOR_ID.test(value);

/** Whether `value` is a factor's kind: a hint token, since a first binding's hints name each kind. */
export const isMfaFactorKind = (value: unknown): value is string => isHintToken(value);

/**
 * Whether `value` is a label a page can show as it is: 1 to
 * {@link MFA_FACTOR_LABEL_MAX_LENGTH} characters, well formed, none of them
 * one that breaks or reorders a line (`lineSafeText` leaves it unchanged).
 */
export const isMfaFactorLabel = (value: unknown): value is string =>
	typeof value === "string" &&
	value.length > 0 &&
	value.length <= MFA_FACTOR_LABEL_MAX_LENGTH * 2 &&
	[...value].length <= MFA_FACTOR_LABEL_MAX_LENGTH &&
	value.isWellFormed() &&
	lineSafeText(value) === value;

/** What an update replaces. Every other field of the record stays as it was. */
export interface MfaFactorRecordUpdate {
	readonly data: string;
	readonly label: string | undefined;
	readonly lastUsedAt: Date | undefined;
}

/** What was asked of `update`: the record, the version expected, and the data written. */
export interface MfaFactorUpdateRequest {
	readonly subject: string;
	readonly id: string;
	readonly expectedVersion: number;
	readonly next: Pick<MfaFactorRecordUpdate, "data">;
}

/**
 * Whether `written`, what `update` answered other than `null`, is the record
 * as the update wrote it: the same subject and id, the version one past the
 * one expected, and the data written. The caller answers anything else —
 * `undefined` among it — as the store's outage, never as a write that
 * happened. Each field is read once.
 */
export function isMfaFactorUpdateWritten(
	written: unknown,
	request: MfaFactorUpdateRequest,
): written is MfaFactorRecord {
	try {
		if (typeof written !== "object" || written === null) return false;
		const { subject, id, version, data } = written as Readonly<Record<string, unknown>>;
		return (
			subject === request.subject &&
			id === request.id &&
			version === request.expectedVersion + 1 &&
			data === request.next.data
		);
	} catch {
		return false;
	}
}

/**
 * Where a subject's second factors are kept.
 *
 * Every operation is atomic on its own. A store that cannot answer throws:
 * an outage is never "no factors", which a caller could read as a subject
 * with nothing enrolled. A rejection after a write was sent is unknown: the
 * write may have committed.
 *
 * **The factor set's store generation.** A subject's records are one set,
 * and the store keeps one generation for it, which lets a writer fence its
 * write against the set it read:
 *
 * - Every membership write — `createIf`, `removeIf`, `create`, `remove`,
 *   `removeAllForSubject` — issues a fresh generation in the same atomic step
 *   as its write. A generation never repeats for a subject: not after a
 *   removal and a re-create, not when the set returns to the same records,
 *   and not after its tombstone has passed. An application-made random UUID
 *   is one; a counter that restarts, a digest of the set and a timestamp are
 *   none.
 * - `update` keeps the generation: it changes a record, not the set's
 *   membership, and its own fence is the record's `version`. A membership
 *   decision that read a record's data is therefore not fenced against an
 *   update of that record. That holds only while every factor's next data
 *   keeps the three things `MfaVerification.next` names.
 * - A set never written has no generation (`null`). A set's generation
 *   outlives its members: the last removal and a reset — account deletion
 *   included — leave the set empty at a new generation, its tombstone,
 *   which a late write read before them meets as a `conflict`. Past the
 *   bound below the tombstone may be purged, and the set then reads as
 *   never written. A set that holds a record is never purged.
 * - A write conditional on a read is valid only within the store's
 *   write-lifetime bound of that read: the bound runs from the versioned read
 *   that produced the write's expected generation to the write's commit or
 *   failure, transport and queues included. The port's owning module keeps it;
 *   callers outside it never hold a generation. An emptied set's tombstone is
 *   kept for at least that bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 h, for
 *   the bundled stores). For MFA, the factor-set writer keeps the bound under
 *   its lease (at most 16 × `mfa.storeTimeoutMs`).
 *   A store adds no delay past the bound: in SQL a statement or
 *   transaction timeout, over HTTP a request deadline never retried once
 *   passed; the bundled memory store (one synchronous step) and Redis
 *   store (one script) add none.
 * - The check and the write are one atomic step in the store, across every
 *   instance on the same backend: a transaction, a script, one synchronous
 *   block. An in-process lock counts only for an in-process store.
 * - A generation is minted, never derived. A set that exists with none — one
 *   only a writer from before these members existed can leave — is given a
 *   fresh one atomically by its first `listVersioned`, and by nothing else: a
 *   conditional write against it answers `conflict` and mints nothing. That
 *   reading is safe only in a fleet with no such writer left: one that
 *   changes the membership without moving the generation would go unfenced.
 *   So a fleet never mixes a build from before the set members with one that
 *   has them.
 *
 * In SQL, keep the set as a row of its own beside the factor rows, and have
 * every membership write take that row first, in one transaction — an
 * upsert of it for `removeAllForSubject` — so the writes lock in one order.
 * `update` takes only the factor's row. `listVersioned` reads the set row
 * and the factor rows in one statement or one snapshot. A set row whose set
 * is empty may be removed once the write-lifetime bound has passed since it
 * was emptied, never before.
 *
 * `listVersioned`, `createIf` and `removeIf` are optional while the bundled
 * adapters gain them, and become required; `create` and `remove` then leave
 * the port.
 */
export interface MfaFactorStore {
	readonly kind: string;
	/** Every record of `subject`, in no particular order; `[]` for a subject with none. */
	list(subject: string): Promise<readonly MfaFactorRecord[]>;
	/**
	 * Every record of `subject`, in no particular order, and the set's
	 * generation, from one snapshot. `generation` is `null` only for a set
	 * never written, or whose tombstone has passed; a set whose records all
	 * went, or that a reset left empty, answers its generation and no records
	 * while its tombstone stands. Read it with {@link readMfaFactorSet}.
	 */
	listVersioned?(subject: string): Promise<VersionedSet<MfaFactorRecord>>;
	/**
	 * Insert `record` only while its subject's set is at `expected`; `null`:
	 * only while the set was never written, which makes a first binding
	 * atomic against a concurrent one. Answers `created` with the set's new
	 * generation, or `conflict` with nothing written: the set at another
	 * generation, absent where `expected` names one, present where `expected`
	 * is `null`, or a `(subject, id)` already held — never overwritten. Never
	 * `missing`. Read it with `readConditionalCreateAnswer`.
	 */
	createIf?(
		record: MfaFactorRecord,
		expected: StoreGeneration | null,
	): Promise<ConditionalCreateAnswer>;
	/**
	 * Remove `(subject, id)` only while the set is at `expected`. Answers
	 * `removed` with the set's new generation (the set stays, empty when that
	 * was its last record); `missing` for no set, or no such record at
	 * `expected`; `conflict` for the set at another generation, checked
	 * before the record. `missing` and `conflict` write nothing, the
	 * generation included. A `removed` without the new generation is no
	 * answer: `readConditionalSetRemoveAnswer` refuses it.
	 */
	removeIf?(
		subject: string,
		id: string,
		expected: StoreGeneration,
	): Promise<ConditionalSetRemoveAnswer>;
	/**
	 * Insert a record, unconditionally, issuing a new generation. Rejects a
	 * `(subject, id)` already present, and leaves that record and the
	 * generation as they were.
	 */
	create(record: MfaFactorRecord): Promise<void>;
	/**
	 * Compare-and-set on `version`: replaces `data`, `label` and `lastUsedAt`
	 * and bumps `version`, only if the record is still at `expectedVersion`.
	 * Answers the record as written, or `null` when the version moved or the
	 * record is gone; it never creates one. Keeps the set's generation.
	 * `Number.MAX_SAFE_INTEGER` as `expectedVersion` is a `RangeError` whatever
	 * the stored version (`checkMfaVersionAdvances`).
	 */
	update(
		subject: string,
		id: string,
		expectedVersion: number,
		next: MfaFactorRecordUpdate,
	): Promise<MfaFactorRecord | null>;
	/** Remove one record, unconditionally. Idempotent. A new generation when it removed one; an emptied set stays as its tombstone. */
	remove(subject: string, id: string): Promise<void>;
	/**
	 * Remove every record of `subject` — account deletion, the operator reset —
	 * unconditionally: it always wins. Leaves the set's tombstone, empty at a
	 * new generation, creating it for a subject never written, so a
	 * conditional write read before it answers `conflict` while the
	 * tombstone stands. Idempotent in what it leaves listed; every call moves
	 * the generation and starts the tombstone's bound again.
	 */
	removeAllForSubject(subject: string): Promise<void>;
}

const RECORD_BINDINGS: ReadonlySet<unknown> = new Set([
	"password",
	"email_proof",
	"federated",
	"mfa",
] satisfies NonNullable<MfaFactorRecord["binding"]>[]);

const isInstant = (value: unknown): value is Date =>
	value instanceof Date && Number.isFinite(value.getTime());

/** `item` as a record of `subject`, its fields each read once; `undefined` for anything else. */
function recordOf(item: unknown, subject: string): MfaFactorRecord | undefined {
	if (typeof item !== "object" || item === null) return undefined;
	const {
		id,
		subject: owner,
		kind,
		label,
		binding,
		createdAt,
		lastUsedAt,
		version,
		data,
	} = item as Readonly<Record<string, unknown>>;
	if (typeof id !== "string" || owner !== subject || typeof kind !== "string") return undefined;
	if (label !== undefined && typeof label !== "string") return undefined;
	if (binding !== undefined && !RECORD_BINDINGS.has(binding)) return undefined;
	if (!isInstant(createdAt) || (lastUsedAt !== undefined && !isInstant(lastUsedAt))) {
		return undefined;
	}
	if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0) {
		return undefined;
	}
	return typeof data === "string" ? (item as MfaFactorRecord) : undefined;
}

/**
 * What `listVersioned` answered for `subject`, read as the port promises it:
 * a versioned set (`readVersionedSet`) whose items are whole records, every
 * field of its type, each naming `subject`, no id twice, and none for a set
 * never written. A fresh frozen answer; the records are the ones answered.
 * Throws a `TypeError` for anything else, a read that throws included — the
 * store's fault, which the caller answers as the store's outage, never as a
 * set with nothing in it.
 */
export function readMfaFactorSet(answer: unknown, subject: string): VersionedSet<MfaFactorRecord> {
	const read = readVersionedSet<unknown>(answer as VersionedSet<unknown>);
	const refuse = (what: string): TypeError =>
		new TypeError(`MfaFactorStore.listVersioned: ${what}`);
	if (read.generation === null && read.items.length > 0) {
		throw refuse("a set never written holds records");
	}
	const ids = new Set<string>();
	for (const item of read.items) {
		let record: MfaFactorRecord | undefined;
		try {
			record = recordOf(item, subject);
		} catch {
			throw refuse("a record could not be read");
		}
		if (record === undefined) throw refuse("an item is not a whole record of the subject");
		if (ids.has(record.id)) throw refuse("a record id repeats");
		ids.add(record.id);
	}
	return read as VersionedSet<MfaFactorRecord>;
}

/** Domain-specific AdapterFactory alias for {@link MfaFactorStore}. */
export type MfaFactorStoreFactory = AdapterFactory<MfaFactorStore>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** Where enrolled second factors are kept. */
		readonly mfaFactorStore?: MfaFactorStore;
	}
}
