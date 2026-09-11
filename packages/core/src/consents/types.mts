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
 * What an end-user has agreed a client may obtain on their behalf (#527).
 *
 * One record per (`sub`, `clientId`): a later grant replaces it, so the record
 * is always the current answer to "what has this user let this client have",
 * and revoking it is one delete.
 */
export interface ConsentRecord {
	readonly sub: string;
	readonly clientId: string;
	/** The scopes the user agreed to. A request for a subset is covered; a superset asks again. */
	readonly scopes: readonly string[];
	/** Epoch milliseconds. */
	readonly grantedAt: number;
	/** Epoch milliseconds; absent means until revoked. */
	readonly expiresAt?: number;
}

/**
 * Where consent records live (#527). Read by `/authorize` for a client that
 * is not first-party — a first-party client never consults it — and written
 * by the consent endpoint when the user accepts.
 *
 * Optional to wire: a deployment that serves first-party clients only has no
 * consent to record. Without it, `/authorize` refuses a client that is not
 * first-party, exactly as it did before the slot existed.
 *
 * Throwing means the store could not answer — a backend being down — and is
 * surfaced as `temporarily_unavailable`, never as a granted or a refused
 * consent: minting a code is an authorization decision, and an outage is not
 * a reason to make it either way.
 */
export interface ConsentStore {
	readonly kind: string;
	find(sub: string, clientId: string): Promise<ConsentRecord | null>;
	/** Replaces any record for the same (`sub`, `clientId`). */
	grant(record: ConsentRecord): Promise<void>;
	/** @returns whether a record was removed. */
	revoke(sub: string, clientId: string): Promise<boolean>;
}

/**
 * Whether `record` covers a request for `scopes` at `nowMs`: it exists, has
 * not expired, and every requested scope is one the user agreed to. An
 * empty request is covered by any live record.
 */
export function consentCovers(
	record: ConsentRecord | null,
	scopes: readonly string[],
	nowMs: number = Date.now(),
): boolean {
	if (record === null) return false;
	if (record.expiresAt !== undefined && record.expiresAt <= nowMs) return false;
	return scopes.every((scope) => record.scopes.includes(scope));
}

// ---------------------------------------------------------------------------
// ComponentMap slot (#527)
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly consentStore?: ConsentStore;
	}
}
