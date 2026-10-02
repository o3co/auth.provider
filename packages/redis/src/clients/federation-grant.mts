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
 * The federation grant store's client: a grant's hash and its sealed credential, each write one
 * guarded script, and the subject's index, reserved and pruned apart from any record.
 */

// --- FederationGrantStoreClient -------------------------------------------

/**
 * A federation grant as it lives in Redis: one HASH per grant, every field a
 * string, beside one STRING holding the sealed credential (ADR
 * 2026-09-17-federation-grants-offline-delegation, D16). The field names are
 * part of the contract, because the scripts read them by name.
 *
 * Two fields are arithmetic rather than record: `retentionMs` (the tombstone
 * retention when the grant was created) and `expiresAtMs` (the
 * authorization's expiry, outside the authenticated text). They decide what
 * Redis reclaims and what a write may touch — never what a caller is told,
 * which is judged on the authenticated text; a rewritten `expiresAtMs` can
 * make a key linger, not disclose a credential past the consented expiry.
 */
export interface FederationGrantHashFields {
	/** The layout's own version, so a later one can be told apart rather than misread. */
	readonly format: string;
	/** JSON `[id, subject, clientId, connection, createdAtMs]`. */
	readonly base: string;
	readonly status: string;
	readonly version: string;
	readonly retentionMs: string;
	/** The canonical authorization text, byte for byte as it was sealed under. Absent before authorization. */
	readonly authorization?: string;
	/** The authorization's `expiresAt`, in epoch milliseconds. Absent before authorization. */
	readonly expiresAtMs?: string;
	/** Guard fields, repeated outside the authenticated text so a script can compare them. */
	readonly identityRevision?: string;
	readonly upstreamIssuer?: string;
	readonly upstreamSubject?: string;
	/** The current intent's opaque handle, JSON-encoded, and when it lapses. Absent when there is none. */
	readonly intentHandle?: string;
	readonly intentExpiresAt?: string;
	readonly lastUsedAt?: string;
	/** JSON `[reason, atMs, judgedAgainst]`. */
	readonly ineligible?: string;
	readonly failureAt?: string;
	readonly failureKind?: string;
	readonly failureCount?: string;
	readonly failureRetryAfterSeconds?: string;
	readonly failureUpstreamCode?: string;
	readonly revokedBy?: string;
	readonly revokedAt?: string;
	/**
	 * The rotation budget's window: when it opened, in epoch milliseconds, and
	 * the rotations taken in it. Written together by `takeRotation`, kept by
	 * every other write but `activate`, which removes both. A record without
	 * both, or with either not a whole number (the count at least 1), has no
	 * window.
	 */
	readonly rotationsSince?: string;
	readonly rotationsCount?: string;
	/**
	 * The credential's extension. Written or removed in the step that writes
	 * the credential, and removed with it. Opens only beside the exact
	 * credential it was written with.
	 */
	readonly ext?: string;
}

export interface CreatePendingFederationGrantInput {
	/** The caller's clock, in epoch milliseconds. */
	readonly nowMs: number;
	/** {@link FederationGrantHashFields.base}, already encoded. */
	readonly base: string;
	/** The intent's handle, JSON-encoded. */
	readonly handle: string;
	readonly intentExpiresAtMs: number;
	readonly retentionMs: number;
}

export interface NameFederationGrantIntentInput {
	readonly nowMs: number;
	readonly handle: string;
	readonly intentExpiresAtMs: number;
}

export interface RetireFederationGrantIntentInput {
	readonly nowMs: number;
	/** When given, the pointer is removed only if this is the handle it holds. */
	readonly handle?: string;
}

export interface ActivateFederationGrantInput {
	readonly nowMs: number;
	/** The intent's handle, JSON-encoded: only the current one activates. */
	readonly handle: string;
	/** The canonical authorization text, byte for byte as the credential was sealed under. */
	readonly authorization: string;
	/** The authorization's expiry, for the arithmetic the scripts do. */
	readonly expiresAtMs: number;
	/** Guard fields, repeated outside the authenticated text so a script can compare them. */
	readonly identityRevision: string;
	readonly upstreamIssuer: string;
	readonly upstreamSubject: string;
	/** The sealed credential. */
	readonly credential: string;
	/** The credential's extension, sealed with it. Absent: the record keeps none. */
	readonly extension?: string;
}

export interface ReplaceFederationGrantCredentialsInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
	readonly credential: string;
	/** The ineligibility marker as JSON `[reason, atMs, judgedAgainst]`, or `null` to remove it. */
	readonly ineligible: string | null;
	/** The new credential's extension, sealed with it. Absent: the record keeps none. */
	readonly extension?: string;
}

export interface RequireFederationGrantReauthorizationInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
}

export interface RevokeFederationGrantInput {
	readonly atMs: number;
	readonly by: string;
}

export interface NoteFederationGrantRefreshFailureInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
	/** When the failure happened, which is what the row is measured from — not `nowMs`. */
	readonly atMs: number;
	readonly kind: string;
	readonly rowMs: number;
	/**
	 * `undefined` when the upstream gave no `Retry-After`. A required key, as
	 * `upstreamCode` is: a store that forgot to pass one would leave a
	 * `rate_limited` stamp with the default backoff where the upstream's
	 * `Retry-After` was longer (both held to the ceiling), or lose the code
	 * that says the user has to come back. A client tells "none" by the value
	 * (`=== undefined`), as `makeIoredisClients` does, not by the key.
	 */
	readonly retryAfterSeconds: number | undefined;
	/** For `rejected`: the upstream's error code. `undefined` otherwise. */
	readonly upstreamCode: string | undefined;
}

export interface TakeFederationGrantRotationInput {
	readonly nowMs: number;
	readonly expectedVersion: number;
	/** The most rotations one window admits: a whole number of at least 1. */
	readonly limit: number;
	/** How long a window lasts, in whole milliseconds above 0. */
	readonly windowMs: number;
}

/** What one read returns: the record and its credential as they were at one instant. */
export interface FederationGrantSnapshot {
	readonly fields: FederationGrantHashFields;
	/** `null` when the key is not there. An empty string is a credential, and not that. */
	readonly credential: string | null;
}

/**
 * The indivisible steps the Redis federation grant store is built from.
 * Every method here is one round trip, and every write is one script: a
 * guard evaluated in the client and a write sent after it would let a
 * concurrent activation, refresh or revocation land in between.
 *
 * A refused write says `null` and nothing else: the record may change again
 * before the caller looks, so the port has it re-read and re-evaluated, and
 * a reason here would oblige two adapters to agree on which precondition
 * wins when several fail at once.
 *
 * Keys are passed in whole: the store owns the layout, and a script that
 * discovered key names inside Lua would not be safe to run on a Cluster.
 */
export interface FederationGrantStoreClient {
	/**
	 * Creates the `pending` record at `grantKey`, at version 1, with its
	 * intent, and takes any credential at `credKey` with it. Refuses when a
	 * record is already there — however far ahead the caller's clock is — and
	 * when the intent's expiry is not after `nowMs`.
	 */
	createPending(
		grantKey: string,
		credKey: string,
		input: CreatePendingFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/** The record and its credential, read together. `null` when there is no record. */
	snapshot(grantKey: string, credKey: string): Promise<FederationGrantSnapshot | null>;
	/** Replaces the intent pointer of an `active` or `reauthorization_required` record, and nothing else. */
	nameIntent(
		grantKey: string,
		input: NameFederationGrantIntentInput,
	): Promise<FederationGrantHashFields | null>;
	/** Removes the intent pointer of an `active` or `reauthorization_required` record, and nothing else. */
	retireIntent(
		grantKey: string,
		input: RetireFederationGrantIntentInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Takes the grant from its current intent to `active` under a new
	 * authorization, sealing the credential with it. Every guard is inside the
	 * script, including the current intent — `nameIntent` and `retireIntent`
	 * bump no version, so a version comparison cannot see a pointer that moved
	 * under a caller that read it.
	 *
	 * A renewal never re-points a grant: the identity revision and the upstream
	 * account must be the ones already recorded. The marker and the stamp of a
	 * failed refresh go with the authorization they were about; a use recorded
	 * before it stays.
	 */
	activate(
		grantKey: string,
		credKey: string,
		input: ActivateFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Replaces the credential of an `active` grant at `expectedVersion`, and
	 * the marker whole — a refresh that found the token eligible removes one.
	 * Forgets the stamp of a failed refresh, and moves no horizon: the
	 * credential's deadline is the authorization's expiry again.
	 */
	replaceCredentials(
		grantKey: string,
		credKey: string,
		input: ReplaceFederationGrantCredentialsInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Takes the credential and its extension, and asks for the user, at
	 * `expectedVersion`. The only transition with no expiry guard: an upstream
	 * that says the credential is dead is believed whenever it says it. The
	 * marker stays, the horizon does not move.
	 */
	requireReauthorization(
		grantKey: string,
		credKey: string,
		input: RequireFederationGrantReauthorizationInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Ends the grant: the credential, its extension and the intent go, what it
	 * was authorized for stays, and the first revocation stays as it was
	 * recorded. No version guard — a revocation does not lose to a refresh in
	 * flight. A revocation moves no horizon, except for a grant that was never
	 * authorized and has no expiry to be retained from.
	 */
	revoke(
		grantKey: string,
		credKey: string,
		input: RevokeFederationGrantInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Stamps a failed refresh on an `active` grant at `expectedVersion`,
	 * counting the stamps in a row, and bumps no version. The version is
	 * still compared: a failure that outlived its refresh must not install a
	 * backoff over a credential written since. Never dated back, and an equal
	 * instant counts onward.
	 */
	noteRefreshFailure(
		grantKey: string,
		input: NoteFederationGrantRefreshFailureInput,
	): Promise<FederationGrantHashFields | null>;
	/**
	 * Takes one rotation from the budget of an `active` grant at
	 * `expectedVersion`, before its stored expiry: a new window
	 * (`rotationsSince` = `nowMs`, `rotationsCount` = 1) when there is none or
	 * `nowMs` is at or past its end, else one more below `limit`, else refused.
	 * Bumps no version and touches no other field. A bound below its minimum
	 * is refused.
	 *
	 * Optional: a store over a client without it keeps no rotation budget.
	 */
	takeRotation?(
		grantKey: string,
		input: TakeFederationGrantRotationInput,
	): Promise<FederationGrantHashFields | null>;
	/** Moves `lastUsedAt` forward, and never back. Writes nothing when there is no record. */
	touch(grantKey: string, atMs: number): Promise<void>;
	/**
	 * Reserves `member` in the subject's index at `horizonMs` — the instant the
	 * record stops answering — and pushes the index's own deadline to the last
	 * horizon it holds plus `allowanceMs`.
	 *
	 * The score only ever moves forward. Two writers lodging one ID both
	 * reserve, and the one whose record is created is not the one that reserved
	 * last: a reservation that lost must not pull the horizon back under the
	 * record that won. A reservation is never withdrawn, for the same reason.
	 */
	reserve(indexKey: string, member: string, horizonMs: number, allowanceMs: number): Promise<void>;
	/** Everything the index holds, nearest horizon first. */
	members(indexKey: string): Promise<readonly string[]>;
	/** `SET key token NX PX ttl`: whether this caller now holds the lock. */
	tryLock(lockKey: string, token: string, ttlMs: number): Promise<boolean>;
	/** Deletes the lock only while its value is still `token`: past the TTL it is somebody else's. */
	unlock(lockKey: string, token: string): Promise<void>;
	/**
	 * Drops members whose horizon passed more than `allowanceMs` before
	 * `clockMs` — the adapter's own clock, as a key TTL is, and never a
	 * caller's. Never by whether the record is there: the index and the record
	 * are different keys, so a member reserved for a record still being written
	 * would be dropped by that rule, and nothing would ever put it back.
	 */
	prune(indexKey: string, clockMs: number, allowanceMs: number): Promise<void>;
}
