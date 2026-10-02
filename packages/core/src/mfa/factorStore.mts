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
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	readVersionedSet,
	type StoreGeneration,
	type VersionedSet,
} from "../adapters/conditionalWrite.mjs";
import { lineSafeText } from "../logging/loggableError.mjs";
import { isHintToken } from "../session-admission/requirement.mjs";

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
 * and the store keeps one generation for its membership, which lets a writer
 * fence its write against the set it read. The set follows core's
 * conditional-write convention for a set (docs/adapter-surface.md,
 * "Conditional writes"); what follows is only what it means here.
 *
 * - The membership writes are `createIf`, `removeIf`, `removeAllForSubject`
 *   and, when a store provides them, `create` and `remove`: each issues a
 *   fresh generation. `update` is a member's own update, fenced by the
 *   record's `version`, and keeps it. A membership decision that read a
 *   record's data is therefore not fenced against an update of that record,
 *   which holds only while every factor's next data keeps the three things
 *   `MfaVerification.next` names.
 * - `removeAllForSubject` (account deletion, the operator reset) is
 *   unconditional and always wins, yet it is one atomic step serialised with
 *   `createIf` and `removeIf`, so neither interleaves with it (rule 1). It
 *   leaves the set as its tombstone, as does a removal of its last record
 *   (rule 6).
 * - Generations are never re-issued (rule 8): a store mints each one at
 *   random, as `newStoreGeneration` does.
 * - The write-lifetime bound (rule 6). The port's owning module is the MFA
 *   package's factor-set writer. A conditional write is issued only under the
 *   subject's lease, from a `listVersioned` read taken under that same lease.
 *   The lease is at most `MFA_SUBJECT_LEASE_MAX_MS` (600 000 ms), so the
 *   write is issued at most the bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`,
 *   24 h) less W after its read; each adapter declares its W well under the
 *   bound. The memory store's W is 0, because its check and write happen in
 *   one synchronous block. The one assumption: the process or the store does
 *   not stall for the whole bound between a `null` read and its commit.
 * - A writer that changes the set's membership but leaves the generation in
 *   place, such as a build from before these members, must not run beside
 *   conditional callers, unless the store moves the generation for it
 *   (rule 8).
 *
 * In SQL, the set's row is the subject's (docs/adapter-surface.md, "A SQL
 * store"), and `update` takes only its factor's row.
 */
export interface MfaFactorStore {
	readonly kind: string;
	/** Every record of `subject`, in no particular order; `[]` for a subject with none. */
	list(subject: string): Promise<readonly MfaFactorRecord[]>;
	/**
	 * Every record of `subject`, in no particular order, and the set's
	 * generation, from one snapshot. `generation` is `null` only for an
	 * absent set: never written, or its tombstone expired; a set whose
	 * records all went, or that a reset left empty, answers its generation
	 * and no records while its tombstone stands. Read it with
	 * {@link readMfaFactorSet}.
	 */
	listVersioned(subject: string): Promise<VersionedSet<MfaFactorRecord>>;
	/**
	 * Insert `record` only while its subject's set is at `expected`; `null`:
	 * only while the set is absent, which makes a first binding atomic against
	 * a concurrent one. A `(subject, id)` already held is a `conflict`, never
	 * overwritten. Read the answer with `readConditionalCreateAnswer`.
	 */
	createIf(
		record: MfaFactorRecord,
		expected: StoreGeneration | null,
	): Promise<ConditionalCreateAnswer>;
	/**
	 * Remove `(subject, id)` only while the set is at `expected`. The set
	 * stays, empty when that was its last record. Read the answer with
	 * `readConditionalSetRemoveAnswer`.
	 */
	removeIf(
		subject: string,
		id: string,
		expected: StoreGeneration,
	): Promise<ConditionalSetRemoveAnswer>;
	/**
	 * Insert a record, unconditionally, issuing a new generation. Rejects a
	 * `(subject, id)` already present, and leaves that record and the
	 * generation as they were. Optional: no bundled module calls it, and it
	 * leaves the port in a later release; a store may still provide it.
	 */
	create?(record: MfaFactorRecord): Promise<void>;
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
	/**
	 * Remove one record, unconditionally. Idempotent. A new generation when it
	 * removed one; a set it empties stays as its tombstone. Optional: no
	 * bundled module calls it, and it leaves the port in a later release; a
	 * store may still provide it.
	 */
	remove?(subject: string, id: string): Promise<void>;
	/**
	 * Remove every record of `subject` — account deletion, the operator reset —
	 * unconditionally: it always wins, as one atomic step serialised with the
	 * conditional writes. Leaves the set's tombstone, empty at a new
	 * generation, creating it for a subject never written, so a conditional
	 * write read before it answers `conflict` while the tombstone stands.
	 * Idempotent in what it leaves listed; every call moves the generation and
	 * starts the tombstone's bound again.
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

/** Every key of {@link MfaFactorRecord}: each a required key, so each must be an own property. */
const RECORD_KEYS = [
	"id",
	"subject",
	"kind",
	"label",
	"binding",
	"createdAt",
	"lastUsedAt",
	"version",
	"data",
] as const satisfies readonly (keyof MfaFactorRecord)[];

/**
 * `item` as a record of `subject`: every key an own property, each read once,
 * and a fresh frozen record built from the values read; `undefined` for
 * anything else.
 */
function recordOf(item: unknown, subject: string): MfaFactorRecord | undefined {
	if (typeof item !== "object" || item === null) return undefined;
	if (!RECORD_KEYS.every((key) => Object.hasOwn(item, key))) return undefined;
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
	if (typeof data !== "string") return undefined;
	return Object.freeze({
		id,
		subject: owner,
		kind,
		label,
		binding: binding as MfaFactorRecord["binding"],
		createdAt,
		lastUsedAt,
		version,
		data,
	});
}

/**
 * What `listVersioned` answered for `subject`, read as the port promises it:
 * a versioned set (`readVersionedSet`) whose items are whole records, every
 * key of its type an own property and every field of its type, each naming
 * `subject`, no id twice, and none for an absent set. A fresh frozen answer
 * whose records are fresh frozen copies, each field of the answered record
 * read once. Throws a `TypeError` for anything else, a read that throws
 * included — the store's fault, which the caller answers as the store's
 * outage, never as a set with nothing in it.
 */
export function readMfaFactorSet(answer: unknown, subject: string): VersionedSet<MfaFactorRecord> {
	const read = readVersionedSet<unknown>(answer as VersionedSet<unknown>);
	const refuse = (what: string): TypeError =>
		new TypeError(`MfaFactorStore.listVersioned: ${what}`);
	const ids = new Set<string>();
	const records: MfaFactorRecord[] = [];
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
		records.push(record);
	}
	return Object.freeze({ items: Object.freeze(records), generation: read.generation });
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
