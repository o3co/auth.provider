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
 * The wire format of the Store's MFA endpoints: the JSON bodies the Store
 * adapter sends and reads, and a Store (or a fake of one) reads and answers.
 * The endpoints, their statuses and what each answer means are
 * `@o3co/auth-provider-foundation`'s README, "The Store's MFA endpoints".
 *
 * Guarantees: times are epoch milliseconds named `…Ms`; an optional field
 * with no value is left out, and `null` is never read as "unset"; what a
 * writer makes, the reader reads back whole, and what the reader refuses,
 * the writer refuses with a `RangeError`; an update carries the expected
 * version and `data`, `label` and `lastUsedAtMs`, nothing else of the record.
 */

import { isStorableExpiry } from "../adapters/expiry.mjs";
import type { MfaFactorRecord, MfaFactorRecordUpdate } from "./factorStore.mjs";
import { checkMfaVersionAdvances } from "./version.mjs";

/** What authorized a binding, as a record carries it. */
export type MfaStoreFactorBinding = NonNullable<MfaFactorRecord["binding"]>;

/** A factor record on the wire: {@link MfaFactorRecord} with its dates as epoch milliseconds. */
export interface MfaStoreFactor {
	readonly id: string;
	readonly subject: string;
	readonly kind: string;
	/** Left out when the factor has none. */
	readonly label?: string;
	/** Left out when none was recorded. */
	readonly binding?: MfaStoreFactorBinding;
	readonly createdAtMs: number;
	/** Left out when the factor was never used. */
	readonly lastUsedAtMs?: number;
	/** A safe non-negative integer; the compare-and-set token. */
	readonly version: number;
	/** Sealed by the provider; the Store keeps it byte for byte and never reads it. */
	readonly data: string;
}

/**
 * The new values of the three fields an update replaces. A `label` or
 * `lastUsedAtMs` left out clears it.
 */
export interface MfaStoreFactorChanges {
	readonly data: string;
	readonly label?: string;
	readonly lastUsedAtMs?: number;
}

/** `listMfaFactors`: every record the Store holds for `subject`. */
export interface MfaStoreListRequest {
	readonly subject: string;
}

/** What `listMfaFactors` answers with a `200`: every record, the ones the provider cannot read included. */
export interface MfaStoreListAnswer {
	readonly factors: readonly unknown[];
}

/** `createMfaFactor`: one new record, refused as a duplicate when its `(subject, id)` is held. */
export interface MfaStoreCreateRequest {
	readonly factor: MfaStoreFactor;
}

/**
 * `updateMfaFactor`: `subject` and `id` name the record, `expectedVersion`
 * is the compare-and-set token, and `changes` is all it writes.
 */
export interface MfaStoreUpdateRequest {
	readonly subject: string;
	readonly id: string;
	readonly expectedVersion: number;
	readonly changes: MfaStoreFactorChanges;
}

/** What `updateMfaFactor` answers with a `200`: the record as written, at `expectedVersion + 1`. */
export interface MfaStoreUpdateAnswer {
	readonly factor: unknown;
}

/** `deleteMfaFactor`: one record, or every record of the subject. */
export type MfaStoreDeleteRequest =
	| { readonly subject: string; readonly id: string }
	| { readonly subject: string; readonly all: true };

/** `markMfaEnrolled`: the enrollment witness the Store answers back as `User.mfaEnrolled`. */
export interface MfaStoreMarkEnrolledRequest {
	readonly subject: string;
	readonly enrolled: boolean;
}

const BINDINGS: ReadonlySet<unknown> = new Set(["password", "email_proof", "mfa"]);
const CHANGE_KEYS: ReadonlySet<string> = new Set(["data", "label", "lastUsedAtMs"]);

const refuse = (what: string): RangeError => new RangeError(`MfaStoreFactor: ${what}`);

const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && isStorableExpiry(value);

const isVersion = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `record[key]` when it is the record's own, else `undefined`. */
const own = (record: Record<string, unknown>, key: string): unknown =>
	Object.hasOwn(record, key) ? record[key] : undefined;

/** The epoch milliseconds of `date`, or a `RangeError` naming `field` for one the reader would refuse. */
function instantOf(date: unknown, field: string): number {
	const ms = date instanceof Date ? date.getTime() : Number.NaN;
	if (!isInstant(ms)) throw refuse(`${field} must be a valid date within the Date range`);
	return ms;
}

function checkString(value: unknown, field: string): string {
	if (typeof value !== "string") throw refuse(`${field} must be a string`);
	return value;
}

/** A record as the wire carries it; a `RangeError` for one {@link readMfaStoreFactor} would not read back. */
export function toMfaStoreFactor(record: MfaFactorRecord): MfaStoreFactor {
	if (record.binding !== undefined && !BINDINGS.has(record.binding)) {
		throw refuse('binding must be "password", "email_proof", "mfa" or absent');
	}
	if (!isVersion(record.version)) throw refuse("version must be a safe non-negative integer");
	return {
		id: checkString(record.id, "id"),
		subject: checkString(record.subject, "subject"),
		kind: checkString(record.kind, "kind"),
		...(record.label !== undefined ? { label: checkString(record.label, "label") } : {}),
		...(record.binding !== undefined ? { binding: record.binding } : {}),
		createdAtMs: instantOf(record.createdAt, "createdAt"),
		...(record.lastUsedAt !== undefined
			? { lastUsedAtMs: instantOf(record.lastUsedAt, "lastUsedAt") }
			: {}),
		version: record.version,
		data: checkString(record.data, "data"),
	};
}

/**
 * `value` as a wire record, when it is one: a fresh object of the record's
 * own fields, any other field left behind. `undefined` for anything else — a
 * field missing, of the wrong type, out of range, or `null` — which the
 * provider holds to be a record it cannot read, never an absent one.
 */
export function readMfaStoreFactor(value: unknown): MfaStoreFactor | undefined {
	if (!isRecord(value)) return undefined;
	const id = own(value, "id");
	const subject = own(value, "subject");
	const kind = own(value, "kind");
	const label = own(value, "label");
	const binding = own(value, "binding");
	const createdAtMs = own(value, "createdAtMs");
	const lastUsedAtMs = own(value, "lastUsedAtMs");
	const version = own(value, "version");
	const data = own(value, "data");
	if (typeof id !== "string" || typeof subject !== "string" || typeof kind !== "string") {
		return undefined;
	}
	if (Object.hasOwn(value, "label") && typeof label !== "string") return undefined;
	if (Object.hasOwn(value, "binding") && !BINDINGS.has(binding)) return undefined;
	if (!isInstant(createdAtMs)) return undefined;
	if (Object.hasOwn(value, "lastUsedAtMs") && !isInstant(lastUsedAtMs)) return undefined;
	if (!isVersion(version) || typeof data !== "string") return undefined;
	return {
		id,
		subject,
		kind,
		...(typeof label === "string" ? { label } : {}),
		...(binding !== undefined ? { binding: binding as MfaStoreFactorBinding } : {}),
		createdAtMs,
		...(lastUsedAtMs !== undefined ? { lastUsedAtMs: lastUsedAtMs as number } : {}),
		version,
		data,
	};
}

/** A wire record {@link readMfaStoreFactor} answered, as the port's record. */
export function fromMfaStoreFactor(factor: MfaStoreFactor): MfaFactorRecord {
	return {
		id: factor.id,
		subject: factor.subject,
		kind: factor.kind,
		label: factor.label,
		binding: factor.binding,
		createdAt: new Date(factor.createdAtMs),
		lastUsedAt: factor.lastUsedAtMs === undefined ? undefined : new Date(factor.lastUsedAtMs),
		version: factor.version,
		data: factor.data,
	};
}

/**
 * An update's `data`, `label` and `lastUsedAtMs` as the wire carries them,
 * and nothing else of `next`, whatever else it holds; a `RangeError` for
 * changes {@link readMfaStoreFactorChanges} would not read back.
 */
export function toMfaStoreFactorChanges(next: MfaFactorRecordUpdate): MfaStoreFactorChanges {
	return {
		data: checkString(next.data, "data"),
		...(next.label !== undefined ? { label: checkString(next.label, "label") } : {}),
		...(next.lastUsedAt !== undefined
			? { lastUsedAtMs: instantOf(next.lastUsedAt, "lastUsedAt") }
			: {}),
	};
}

/**
 * `value` as an update's changes, when it is: `data`, and `label` and
 * `lastUsedAtMs` when present, in a fresh object. `undefined` when a field is
 * of the wrong type or `null`, and when any other field is present — one a
 * Store must not change.
 */
export function readMfaStoreFactorChanges(value: unknown): MfaStoreFactorChanges | undefined {
	if (!isRecord(value)) return undefined;
	if (Object.keys(value).some((key) => !CHANGE_KEYS.has(key))) return undefined;
	const data = own(value, "data");
	const label = own(value, "label");
	const lastUsedAtMs = own(value, "lastUsedAtMs");
	if (typeof data !== "string") return undefined;
	if (Object.hasOwn(value, "label") && typeof label !== "string") return undefined;
	if (Object.hasOwn(value, "lastUsedAtMs") && !isInstant(lastUsedAtMs)) return undefined;
	return {
		data,
		...(typeof label === "string" ? { label } : {}),
		...(lastUsedAtMs !== undefined ? { lastUsedAtMs: lastUsedAtMs as number } : {}),
	};
}

/**
 * The body of an update of `(subject, id)` at `expectedVersion`. A
 * `RangeError` for an `expectedVersion` that is no version, or at
 * `Number.MAX_SAFE_INTEGER` (`checkMfaVersionAdvances`), and for changes
 * {@link toMfaStoreFactorChanges} refuses.
 */
export function toMfaStoreUpdateRequest(
	subject: string,
	id: string,
	expectedVersion: number,
	next: MfaFactorRecordUpdate,
): MfaStoreUpdateRequest {
	checkMfaVersionAdvances(expectedVersion, "MfaStoreUpdateRequest");
	if (!isVersion(expectedVersion)) {
		throw refuse("expectedVersion must be a safe non-negative integer");
	}
	return {
		subject: checkString(subject, "subject"),
		id: checkString(id, "id"),
		expectedVersion,
		changes: toMfaStoreFactorChanges(next),
	};
}
