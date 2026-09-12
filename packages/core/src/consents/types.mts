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
	/**
	 * Records consent for the (`sub`, `clientId`) pair, as the **union** of
	 * `record.scopes` and any scopes already recorded for that pair — never
	 * as a replacement. Two browsers consenting to different scopes at the
	 * same time would otherwise lose one of the grants, and the one lost is
	 * the one the user already answered for. `grantedAt` and `expiresAt` are
	 * the new record's.
	 *
	 * An adapter over a store with a compare-and-set or a set type should use
	 * it; the union is the contract, not the read-modify-write.
	 */
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
// The parked request (#552)
// ---------------------------------------------------------------------------

/**
 * An `/authorize` request parked while the user is asked for consent (#552).
 *
 * Addressed by its `challenge` — 32 random bytes, handed to the deployment's
 * consent page through the redirect URL and nowhere else — and bound to the
 * session that parked it and the subject it was asked of: the challenge
 * presented from any other session answers nothing. `expiresAt` bounds how
 * long the page has; a record past it is gone whichever way it is read.
 */
export interface PendingConsentRecord {
	readonly challenge: string;
	/** The express session that parked the request. Only it may answer. */
	readonly sessionId: string;
	/** The subject consent is asked of; the answer has to come from them. */
	readonly sub: string;
	readonly clientId: string;
	/** The scopes the request asks for, after the client's allowlist. */
	readonly scopes: readonly string[];
	/** What the user already agreed to for this client, for the page's delta. */
	readonly grantedScopes: readonly string[];
	/** The `/authorize` request to return to once consent is recorded. */
	readonly authorizeUrl: string;
	/** The validated `redirect_uri`, where a denial goes. */
	readonly redirectUri: string;
	readonly state?: string;
	/** Epoch milliseconds. */
	readonly createdAt: number;
	/** Epoch milliseconds. */
	readonly expiresAt: number;
}

/**
 * Where a parked request waits for its answer (#552).
 *
 * A record of its own, not a field on the session. express-session hands
 * every request a snapshot and writes it back on save, so two answers in
 * flight for one challenge both read the challenge, both pass, and both
 * apply — an accept and a deny, in either order, with the accept's grant
 * standing although the user denied. A record that `consume` returns and
 * removes in one step is what makes the second answer find nothing. The
 * federation callback keeps its ephemeral state the same way (#494).
 *
 * `consume` is the port's reason to exist and the one operation an adapter
 * has to get right: read and remove atomically — `GETDEL` on Redis, never a
 * `GET` followed by a `DEL`. `get` is the page's read of what is being
 * asked, and must not spend the record.
 *
 * Wired together with `consentStore`: the bundled memory module provides
 * both, and the consent step is mounted only when both are present. A
 * store that cannot answer throws, and is surfaced as
 * `temporarily_unavailable`, never as an answer either way.
 */
export interface PendingConsentStore {
	readonly kind: string;
	set(record: PendingConsentRecord): Promise<void>;
	/** The record, or `null` when there is none or it has expired. Does not spend it. */
	get(challenge: string): Promise<PendingConsentRecord | null>;
	/** The record, removed in the same step — or `null` when there was nothing to remove. */
	consume(challenge: string): Promise<PendingConsentRecord | null>;
}

// ---------------------------------------------------------------------------
// ComponentMap slots (#527, #552)
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly consentStore?: ConsentStore;
		readonly pendingConsentStore?: PendingConsentStore;
	}
}
