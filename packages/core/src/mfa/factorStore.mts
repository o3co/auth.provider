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
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
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
	 * `mfa`: recent MFA, beside another factor.
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
 * with nothing enrolled.
 */
export interface MfaFactorStore {
	readonly kind: string;
	/** Every record of `subject`, in no particular order; `[]` for a subject with none. */
	list(subject: string): Promise<readonly MfaFactorRecord[]>;
	/** Insert a record. Rejects a `(subject, id)` already present, and leaves that record as it was. */
	create(record: MfaFactorRecord): Promise<void>;
	/**
	 * Compare-and-set on `version`: replaces `data`, `label` and `lastUsedAt`
	 * and bumps `version`, only if the record is still at `expectedVersion`.
	 * Answers the record as written, or `null` when the version moved or the
	 * record is gone. `Number.MAX_SAFE_INTEGER` as `expectedVersion` is a
	 * `RangeError` whatever the stored version (`checkMfaVersionAdvances`).
	 */
	update(
		subject: string,
		id: string,
		expectedVersion: number,
		next: MfaFactorRecordUpdate,
	): Promise<MfaFactorRecord | null>;
	/** Remove one record. Idempotent. */
	remove(subject: string, id: string): Promise<void>;
	/** Remove every record of `subject` — account deletion, the operator reset. Idempotent. */
	removeAllForSubject(subject: string): Promise<void>;
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
