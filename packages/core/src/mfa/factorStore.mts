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
 * The enrolled-factor record and the port that keeps it (the MFA ADR's D7),
 * with its `mfaFactorStore` slot.
 *
 * A record is one second factor bound to one subject. Its `data` is the
 * factor's own state, sealed by the coordinator before it reaches the store
 * (D11), and opaque to every store: kept byte for byte, never decoded,
 * logged or derived from. "Only zero records open a first binding" (F3) is
 * only as strong as this store, which is why losing it is guarded
 * separately (D12, the enrollment witness on `UserRepository`).
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

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
	/** What authorized the binding (D24): recorded for audit, not enforced. */
	readonly binding: "password" | "email_proof" | "mfa" | undefined;
	readonly createdAt: Date;
	readonly lastUsedAt: Date | undefined;
	/** Bumped by every update; the compare-and-set token. */
	readonly version: number;
	/** The factor's own state, sealed (D11). Opaque to every store. */
	readonly data: string;
}

/** What an update replaces. Every other field of the record stays as it was. */
export interface MfaFactorRecordUpdate {
	readonly data: string;
	readonly label: string | undefined;
	readonly lastUsedAt: Date | undefined;
}

/**
 * Where a subject's second factors are kept.
 *
 * Every operation is atomic on its own. A store that cannot answer throws:
 * an outage is never "no factors" (D28), which a caller could read as a
 * subject with nothing enrolled.
 */
export interface MfaFactorStore {
	readonly kind: string;
	/** Every record of `subject`, in no particular order; `[]` for a subject with none. */
	list(subject: string): Promise<readonly MfaFactorRecord[]>;
	/** Insert a record. Rejects a `(subject, id)` already present, and leaves that record as it was. */
	create(record: MfaFactorRecord): Promise<void>;
	/**
	 * Compare-and-set on `version`: replaces `data`, `label` and `lastUsedAt`
	 * and bumps `version` by one, only if the record is still at
	 * `expectedVersion`. Answers the record as written, or `null` when the
	 * version moved or the record is gone.
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
		/** Where enrolled second factors are kept (the MFA ADR's D7). */
		readonly mfaFactorStore?: MfaFactorStore;
	}
}
