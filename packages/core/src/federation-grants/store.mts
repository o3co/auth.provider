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

import type {
	FederationGrant,
	FederationGrantAuthorization,
	FederationGrantCredentials,
	FederationGrantIneligibilityMarker,
	FederationGrantRefreshFailureInput,
	FederationGrantRevokedBy,
} from "./types.mjs";

/**
 * The store of federation grants (#593, D2, D16): the records, the upstream
 * credentials sealed beside them, and the lock a refresh holds.
 *
 * **Every transition is a guarded write inside the store.** A revoked or
 * expired grant must never become usable again, and declaring that is not
 * enough: each write below checks its preconditions and applies its effects as
 * one atomic step, against the record as it is at that instant. An adapter
 * that reads, decides and writes in separate round trips is not an
 * implementation of this port, and the contract suite runs conflicting writes
 * concurrently to say so.
 *
 * **A write that fails says only that it failed.** The record may have been
 * revoked, replaced by another refresh, or expired; it may change again before
 * the caller looks. So the caller does not act on why: it re-reads and
 * re-evaluates from the top (D2), and never uses what it fetched for a grant
 * it could not write.
 *
 * **Time is the caller's.** Every operation on a record takes the time from
 * its caller, sampled at the write and not at the start of the request: a
 * refresh that starts before `expiresAt` and finishes after it must fail.
 * What a caller is told is judged on that time alone. What an adapter
 * reclaims is judged on the adapter's own clock, as a key TTL is: a TTL is a
 * safety net, never the rule, and a `now` that is wrong for one call must not
 * cost a record: no operation, read or write, deletes anything because of the
 * time its caller passed. A time that is not a date is refused with a
 * `RangeError`, and not compared — every comparison with NaN is false, and the
 * record would read as lapsed.
 *
 * **What is not here.** The intent records — the redirect URI, the scopes, the
 * consent challenge — the connect transactions, and the bound on live intents
 * belong to a second port that arrives with acquisition. D16 keeps them under
 * another key tag and needs no atomicity between the two, so the order of the
 * two writes is core's to decide once, and not each adapter's. What a grant
 * record knows of an intent is a pointer: its handle, and when it lapses.
 */
export interface FederationGrantStore {
	/** Non-empty; names the adapter in logs and diagnostics. */
	readonly kind: string;

	/**
	 * Creates the `pending` record of a first-time intent, naming that intent as
	 * current (D2, D6). Fails when the ID is taken, whatever state that record is
	 * in — and taken means that a record is THERE, not that this caller can see
	 * it: a caller whose clock is ahead must not lodge over a record that is
	 * still live for everyone else. The record lives until `intent.expiresAt`
	 * unless it is activated or revoked first: a first intent that lapses unused
	 * takes its grant with it, and so does a first consent the user declines —
	 * declining spends the intent record before any callback can exist, so
	 * nothing can reach `activate`, and the grant is left to lapse.
	 */
	createPending(input: {
		readonly id: string;
		readonly subject: string;
		readonly clientId: string;
		readonly connection: string;
		readonly intent: FederationGrantIntentPointer;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Names the intent of a reauthorization as current, superseding any other
	 * (D2). The grant must be `active` or `reauthorization_required`, and
	 * `now < expiresAt`. A `pending` grant is refused: a first-time intent makes
	 * a new grant, and never takes over another one's.
	 *
	 * Changes nothing a client can see, and does not bump `version`: a refresh
	 * in flight must not lose its write to a reauthorization the user may never
	 * finish.
	 */
	nameIntent(input: {
		readonly grantId: string;
		readonly intent: FederationGrantIntentPointer;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Whether an activation with `handle` could still succeed, as far as the
	 * record says: it is the grant's current intent, it has not lapsed, and —
	 * unless the grant is `pending` — `now` is before the stored `expiresAt`. The
	 * connect callback asks before it exchanges the code (D7), which an
	 * activation at the end cannot stand in for: a code exchanged for a grant
	 * that can no longer be activated leaves a refresh token at the upstream
	 * that nothing will ever use. `false` for an unknown grant, a revoked one, a
	 * superseded or retired handle, and a lapsed intent alike.
	 *
	 * Asking spends nothing: it may be asked any number of times.
	 *
	 * The handle is never part of {@link FederationGrant}: what the reads return
	 * goes into responses. It is opaque to the store, which compares it and does
	 * nothing else with it; core may hand over a digest in place of the value
	 * the browser carries.
	 */
	isCurrentIntent(grantId: string, handle: string, now: Date): Promise<boolean>;

	/**
	 * Retires the current intent of an `active` or `reauthorization_required`
	 * grant, and changes nothing else: no `version` bump, for the reason
	 * `nameIntent` has none. With `handle`, only if that is the current one — a
	 * consent refused for a superseded intent must not end the newer one.
	 * Without, whichever is current: a subject-wide revocation that keeps the
	 * subject's established grants still ends every renewal in flight (D13), and
	 * by then the pointer on the grant is the only thing left to end.
	 *
	 * Fails when there is nothing to retire, and for a `pending` grant, whose
	 * first intent is its life: that grant lapses with it, or is revoked.
	 */
	retireIntent(input: {
		readonly grantId: string;
		readonly handle?: string;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * The record, or `null`. A `pending` grant whose intent has lapsed reads as
	 * absent. An authorized grant past its `expiresAt` is still returned, for as
	 * long as the adapter retains it, so that the status route can answer
	 * `expired` and not `grant_not_found`.
	 */
	find(grantId: string, now: Date): Promise<FederationGrant | null>;

	/** Every record of the subject that `find` would return, in no particular order. */
	listBySubject(subject: string, now: Date): Promise<readonly FederationGrant[]>;

	/**
	 * The record, and whether its credential would open, without the credential
	 * leaving the store. For the status route (D9).
	 */
	inspect(grantId: string, now: Date): Promise<FederationGrantInspection | null>;

	/**
	 * The record and its credential, as ONE snapshot. The caller evaluates the
	 * grant that comes back, and not one it read earlier: a credential is bound
	 * to the authorization fields of the record it was sealed under (D16), so
	 * opening it against a record read before a concurrent activation would
	 * report a good credential as unreadable — and opening it by ID alone would
	 * hand back credentials for an authorization the caller never evaluated.
	 *
	 * `unreadable` and `key_unavailable` are results, not throws. Nothing is
	 * deleted because it could not be read (D16).
	 */
	open(grantId: string, now: Date): Promise<FederationGrantOpened | null>;

	/**
	 * The connect callback succeeded (D2). Preconditions, all at `now`:
	 *
	 * - the grant is `pending`, `active` or `reauthorization_required`;
	 * - unless `pending`, `now` is before the STORED `expiresAt` — a new consent
	 *   must not resurrect a grant whose consented lifetime has ended;
	 * - `intentHandle` is the grant's current intent, and it has not lapsed;
	 * - the NEW `authorization.expiresAt` is after `now`, and within the
	 *   lifetime ceiling of `authorization.consent.at` (D3);
	 * - `authorization.consent.at` and `authorizedAt` are not after `now`, with
	 *   no allowance: the revocation backstop compares the consent with a
	 *   boundary (D13), and a boundary stamped from this write on must always
	 *   cover it. The comparison there has its own allowance for two replicas'
	 *   clocks; any added here would come on top of it, and a consent dated
	 *   thirty seconds ahead would slip past a revocation stamped ten seconds
	 *   later — for good, since neither instant ever changes;
	 * - every date in the authorization and the credentials is a date;
	 * - unless the grant is `pending`, the authorization names the same upstream
	 *   account and the same identity revision as the stored one. A renewal
	 *   never re-points a grant (D4, D7): the connect callback checks the account
	 *   before it gets here, and this is the same rule at the write, so that one
	 *   slip there cannot hand a grant ID to another upstream account.
	 *
	 * Effects: `active`; the authorization fields replaced as a whole; the
	 * credentials replaced as a whole; the ineligibility marker cleared; the
	 * intent retired, so that the same handle cannot activate twice; `version`
	 * bumped. `lastUsedAt` stays. A refused activation leaves the grant, its
	 * credentials and its intent exactly as they were (D7).
	 */
	activate(input: {
		readonly grantId: string;
		readonly intentHandle: string;
		readonly authorization: FederationGrantAuthorization;
		readonly credentials: FederationGrantCredentials;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * A refresh (D2, D5). The grant must be `active`, its `version` the one the
	 * caller read, and `now` before `expiresAt`.
	 *
	 * The credentials are replaced as a whole, not merged: with `accessToken`
	 * absent the record keeps the refresh token only, which is how an ineligible
	 * access token is never written. The marker is set, or with `null` cleared,
	 * in the same write. `version` is bumped, and the current intent is left
	 * alone: a refresh in the background must not cost the user the
	 * reauthorization they are in the middle of. A date that is not one refuses
	 * the write.
	 */
	replaceCredentials(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly credentials: FederationGrantCredentials;
		readonly ineligible: FederationGrantIneligibilityMarker | null;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * The upstream answered a structured `invalid_grant` (D12). The grant must
	 * be `active` and its `version` the one the caller read. It becomes
	 * `reauthorization_required`, its credentials are deleted, and `version` is
	 * bumped; every other field stays as it is, the current intent included.
	 * `now` decides only whether the record is there to write to: an expired
	 * grant is still marked, and its expiry is what is reported (D1).
	 */
	requireReauthorization(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Ends the grant: `revoked`, the revocation recorded, the credentials
	 * deleted, the intent retired, `version` bumped, every other field as it was
	 * — one atomic step that always wins, with no version to match. It ends a
	 * grant in any other state, one past its expiry included: a client that
	 * revokes is told `revoked`, and not that the grant had expired anyway.
	 *
	 * `ok` is whether it changed anything: `false` for an unknown grant, and for
	 * one already revoked, whose first revocation stays as recorded.
	 */
	revoke(grantId: string, by: FederationGrantRevokedBy, at: Date): Promise<FederationGrantWrite>;

	/**
	 * A refresh failed (D12). The grant must be `active`, its `version` the one
	 * the caller read — a failure of a refresh token the grant no longer has
	 * says nothing about the one it has now — and `now` before `expiresAt`. A
	 * date that is not one refuses the write.
	 *
	 * Effect: `refreshFailure` set, with `count` one more than the stamp it
	 * replaces, or `1`. It does not bump `version` — it must not cost anybody a
	 * guarded write, and nothing reads it as a state of the grant — and it
	 * touches nothing else. It is cleared by whatever replaces or ends the
	 * credentials: `replaceCredentials`, `activate`, `requireReauthorization`,
	 * `revoke`. An adapter writes it atomically: a read, a count and a write in
	 * three steps would lose a stamp to a `touch`, and a count to a second stamp.
	 */
	noteRefreshFailure(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly failure: FederationGrantRefreshFailureInput;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Sets `lastUsedAt` on an `active` grant, and never moves it back: two
	 * retrievals may report out of order. It does not bump `version`, and does
	 * nothing for any other grant, nor for an `at` that is not a date.
	 *
	 * Best effort, and that is the caller's part: a store may reject when it
	 * cannot be reached, and the retrieval that called it answers as if it had
	 * not.
	 */
	touch(grantId: string, at: Date): Promise<void>;

	/**
	 * The lock a refresh holds (D12), keyed by grant. Waits up to `waitForMs`
	 * for a holder to release, and never acquires after that: `0` is a single
	 * attempt, and a lock released just past the deadline is not taken, since
	 * the caller has given up by then. The lock has no renewal:
	 * past `ttlMs` another caller may acquire it, and the first holder's
	 * `release` must then leave the second holder's lock alone. `release` is
	 * idempotent.
	 *
	 * A rejection is a client-level failure — the lock could not be asked for —
	 * and not a lock that is held. `ttlMs` must be a positive finite number and
	 * `waitForMs` a non-negative one, or the call rejects with a `RangeError`:
	 * a TTL of NaN compares as already expired, and exclusion would be silently
	 * off — two refreshes presenting one refresh token (D12).
	 */
	acquireRefreshLock(
		grantId: string,
		options: { readonly ttlMs: number; readonly waitForMs: number },
	): Promise<FederationGrantLockResult>;
}

/** What a grant record knows of an intent (D2): which one is current, and until when. */
export interface FederationGrantIntentPointer {
	/** Opaque to the store. Single-use, 256 bits of entropy behind it (D6). */
	readonly handle: string;
	readonly expiresAt: Date;
}

/** The record as the write left it, or only that the write did not happen. */
export type FederationGrantWrite =
	| { readonly ok: true; readonly grant: FederationGrant }
	| { readonly ok: false };

/**
 * - `absent` — no credential record. Expected for every grant that is not
 *   `active`, whose credentials a transition deleted; for an `active` one the
 *   caller reads it as unreadable (D1).
 * - `unreadable` — it does not authenticate under the current key ring, or
 *   against the record's authorization fields.
 * - `key_unavailable` — sealed under a key that is not in the ring: an outage,
 *   and the record is kept (D16).
 */
export type FederationGrantCredentialState = "ok" | "absent" | "unreadable" | "key_unavailable";

export interface FederationGrantInspection {
	readonly grant: FederationGrant;
	readonly credentials: FederationGrantCredentialState;
}

export interface FederationGrantOpened {
	readonly grant: FederationGrant;
	readonly credentials:
		| { readonly state: "ok"; readonly value: FederationGrantCredentials }
		| { readonly state: Exclude<FederationGrantCredentialState, "ok"> };
}

export type FederationGrantLockResult =
	| {
			readonly acquired: true;
			/**
			 * How long the store waited for the lock before it TOOK it, in
			 * milliseconds: `0` for one taken at once. A duration, not an instant,
			 * so that it means the same on the caller's clock as on the store's.
			 * The holder counts every deadline from when it asked plus this (D12),
			 * never from when the acquisition was acknowledged — an acknowledgement
			 * that took a second would otherwise overstate what is left of the lock
			 * by that second, and a slow enough one lets a second holder in while
			 * the first still refreshes.
			 */
			readonly waitedMs: number;
			readonly release: () => Promise<void>;
	  }
	| { readonly acquired: false; readonly reason: "timeout" };

// ---------------------------------------------------------------------------
// ComponentMap slot (#593)
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationGrantStore?: FederationGrantStore;
	}
}
