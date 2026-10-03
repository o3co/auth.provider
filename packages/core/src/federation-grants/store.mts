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
	FederationGrantCredentialsInput,
	FederationGrantIneligibilityMarker,
	FederationGrantRefreshFailureInput,
	FederationGrantRevokedBy,
} from "./types.mjs";

/**
 * The federation-grant store port: the records, the upstream credentials
 * sealed beside them, and the lock a refresh holds.
 *
 * Every transition is a guarded write: preconditions checked and effects
 * applied as one atomic step against the record as it is at that instant, so a
 * revoked or expired grant can never become usable again. An adapter that
 * reads, decides and writes in separate round trips does not implement this
 * port; the contract suite runs conflicting writes concurrently.
 *
 * A failed write says only that it failed. The caller re-reads and re-evaluates
 * from the top, and never uses what it fetched for a grant it could not write.
 *
 * Time is the caller's, sampled at the write (a refresh that starts before
 * `expiresAt` and finishes after it must fail), and decides what the caller is
 * told. What an adapter reclaims is judged on its own clock, like a key TTL: no
 * operation deletes anything because of the time its caller passed, but what
 * the adapter's clock has reclaimed is gone for every caller. A time that is
 * not a date is refused with a `RangeError` (every comparison with NaN is
 * false). A non-finite number or a non-integer version the record would keep
 * refuses the write (`{ ok: false }`). A bound that is only compared, such as
 * `rowMs`, is compared as given.
 *
 * Intent records, connect transactions and the intent bound belong to
 * `FederationGrantIntentStore`, under another key tag with no atomicity between
 * the two; core orders the two writes. A grant knows an intent only by a
 * pointer: its handle, and when it lapses.
 */
export interface FederationGrantStore {
	/** Non-empty; names the adapter in logs and diagnostics. */
	readonly kind: string;

	/**
	 * Creates the `pending` record of a first-time intent, naming it current.
	 * Fails when a record is there under the ID, in any state, even one this
	 * caller's clock cannot see (a clock ahead must not lodge over a live
	 * record). Lives until `intent.expiresAt` unless activated or revoked: a
	 * first intent that lapses unused, or a first consent declined (which spends
	 * the intent before any callback), takes the grant with it.
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
	 * Names a reauthorization's intent current, superseding any other. The grant
	 * must be `active` or `reauthorization_required` with `now < expiresAt`; a
	 * `pending` grant is refused (a first-time intent never takes over another
	 * grant). Does not bump `version`: a refresh in flight must not lose its
	 * write to a reauthorization the user may never finish.
	 */
	nameIntent(input: {
		readonly grantId: string;
		readonly intent: FederationGrantIntentPointer;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Whether an activation with `handle` could still succeed as far as the
	 * record says: the current intent, not lapsed, and (unless `pending`) `now`
	 * before the stored `expiresAt`. The connect callback asks before exchanging
	 * the code, since a code exchanged for a grant that cannot be activated
	 * leaves an unused refresh token at the upstream. `false` for an unknown,
	 * revoked, superseded, retired or lapsed case alike. Spends nothing.
	 *
	 * The handle is a capability the browser carries: never part of
	 * {@link FederationGrant} (reads go into responses), opaque to the store, and
	 * compared in constant time here and in every write that takes one. Core may
	 * pass a digest instead.
	 */
	isCurrentIntent(grantId: string, handle: string, now: Date): Promise<boolean>;

	/**
	 * Retires the current intent of an `active` or `reauthorization_required`
	 * grant and changes nothing else (no `version` bump). With `handle`, only if
	 * it is current, so a consent refused for a superseded intent cannot end the
	 * newer one; without, whichever is current, so a subject-wide revocation that
	 * keeps established grants still ends renewals in flight. Fails when nothing
	 * is current, and for a `pending` grant, whose first intent is its life.
	 */
	retireIntent(input: {
		readonly grantId: string;
		readonly handle?: string;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * The record, or `null`. A `pending` grant whose intent lapsed reads as
	 * absent; an authorized grant past `expiresAt` is still returned while the
	 * adapter retains it, so the status route can answer `expired`. That
	 * tombstone retention is fixed per record at creation: a store reopened
	 * under another setting applies it only to records it creates from then.
	 */
	find(grantId: string, now: Date): Promise<FederationGrant | null>;

	/** Every record of the subject that `find` would return, in no particular order. */
	listBySubject(subject: string, now: Date): Promise<readonly FederationGrant[]>;

	/**
	 * The record, and whether its credential would open, without the credential
	 * leaving the store. For the status route.
	 */
	inspect(grantId: string, now: Date): Promise<FederationGrantInspection | null>;

	/**
	 * The record and its credential as one snapshot; the caller evaluates the
	 * grant that comes back, not one read earlier. A credential is bound to the
	 * authorization fields it was sealed under, so opening it against an older
	 * read would report a good credential unreadable, and opening by ID alone
	 * would return credentials for an authorization never evaluated.
	 * `unreadable` and `key_unavailable` are results, not throws; nothing is
	 * deleted because it could not be read.
	 */
	open(grantId: string, now: Date): Promise<FederationGrantOpened | null>;

	/**
	 * The connect callback succeeded. Preconditions, all at `now`:
	 *
	 * - the grant is `pending`, `active` or `reauthorization_required`, and
	 *   unless `pending`, `now` is before the stored `expiresAt` (a new consent
	 *   must not resurrect a grant whose consented lifetime ended);
	 * - `intentHandle` is the current intent and has not lapsed;
	 * - the new `authorization.expiresAt` is after `now` and within the lifetime
	 *   ceiling of `authorization.consent.at`;
	 * - `authorization.consent.at` and `authorizedAt` are not after `now`, with
	 *   no allowance: the revocation backstop compares the consent with a
	 *   boundary that already allows for replica clock skew, and a consent dated
	 *   ahead would slip past a later revocation for good;
	 * - every date is a date, and an access token's issued lifetime is finite;
	 * - unless `pending`, the same upstream account and identity revision as
	 *   stored: a renewal never re-points a grant to another upstream account.
	 *
	 * Effects: `active`; authorization fields and credentials replaced whole;
	 * the ineligibility marker and `rotations` cleared; the intent retired (no
	 * double activation); `version` bumped; `lastUsedAt` kept. A refused
	 * activation changes nothing.
	 */
	activate(input: {
		readonly grantId: string;
		readonly intentHandle: string;
		readonly authorization: FederationGrantAuthorization;
		readonly credentials: FederationGrantCredentialsInput;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * A refresh. The grant must be `active`, at the caller's `version`, with
	 * `now` before `expiresAt`. Credentials are replaced whole (with
	 * `accessToken` `undefined` only the refresh token is kept, so an ineligible
	 * access token is never written); the marker is set, or cleared with `null`,
	 * in the same write; `version` is bumped; the current intent is left alone,
	 * so a background refresh cannot cost the user a reauthorization in
	 * progress; `rotations` is kept, since the rotation it counts is the one
	 * this write records. Refused: an invalid date, a non-integer version, a non-finite
	 * issued lifetime or `judgedAgainst`, and a credential the store's own clock
	 * already reclaimed (else the write would land beside a record the caller
	 * next reads as `absent`).
	 */
	replaceCredentials(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly credentials: FederationGrantCredentialsInput;
		readonly ineligible: FederationGrantIneligibilityMarker | null;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * The upstream answered a structured `invalid_grant`. The grant must be
	 * `active` at the caller's `version`. It becomes `reauthorization_required`,
	 * its credentials are deleted and `version` is bumped; every other field
	 * stays, the current intent included. `now` decides only whether the record
	 * is there: an expired grant is still marked, and its expiry is reported.
	 */
	requireReauthorization(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Ends the grant in one atomic step that always wins, with no version to
	 * match: `revoked`, the revocation recorded, credentials deleted, intent
	 * retired, `version` bumped. Applies in any state, even past expiry, so a
	 * revoking client is told `revoked`.
	 *
	 * `ok` is whether it changed anything: `false` for an unknown or already
	 * revoked grant (the first revocation stands). A record the adapter cannot
	 * read is still revoked and its credentials deleted, but answers `false`,
	 * since `ok: true` must carry a grant and there is none to carry.
	 */
	revoke(grantId: string, by: FederationGrantRevokedBy, at: Date): Promise<FederationGrantWrite>;

	/**
	 * A refresh failed. The grant must be `active`, at the caller's `version` (a
	 * failure of a refresh token the grant no longer has says nothing), with
	 * `now` before `expiresAt`. Refused: an invalid date, a non-integer version,
	 * a non-finite `retryAfterSeconds`, and a stamp dated before the one it would
	 * replace (a late write must not land over a newer failure).
	 *
	 * Sets `refreshFailure`, with `count` one more than the stamp it replaces if
	 * that one is within `rowMs` of `failure.at`, else `1`. A stamp carrying an
	 * interaction code (`federationGrantInteractionCode`) is never replaced by a
	 * later stamp: it is what makes the grant read `reauthorization_required`.
	 * No `version` bump, nothing else touched. Cleared by whatever replaces or
	 * ends the credentials (`replaceCredentials`, `activate`,
	 * `requireReauthorization`, `revoke`). Written atomically, so a `touch` or a
	 * second stamp cannot lose a stamp or a count.
	 */
	noteRefreshFailure(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly failure: FederationGrantRefreshFailureInput;
		/**
		 * How far apart two failures may be and still count as a row, compared in
		 * whole milliseconds as the instants are: a fraction is a bound, never
		 * rounded into a match.
		 */
		readonly rowMs: number;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Takes one upstream refresh-token rotation from the grant's rotation
	 * budget, before the upstream is asked. A rotation here is a refresh the
	 * upstream may have acted on, whether or not it issued a new refresh
	 * token. The grant must be `active`, at the caller's `version`, with `now`
	 * before `expiresAt`. Then, in one atomic step against `rotations`:
	 *
	 * - none, a `since` that holds no instant, or `now` at or after
	 *   `since + windowMs`: a new window, `{ since: now, count: 1 }`;
	 * - else, `count` below `limit`: `count + 1`;
	 * - else the budget is spent, and the write is refused.
	 *
	 * No `version` bump, nothing else touched. Kept by `replaceCredentials`,
	 * reset by `activate`.
	 *
	 * The window is fixed, not sliding: it opens at its first take, so any
	 * `windowMs` that straddles two windows can hold up to twice `limit` takes.
	 *
	 * Bounds are checked before the record, and rejected with a `RangeError`, as
	 * a `now` that is not a date is: a `limit` that is not a whole number of at
	 * least `1` (`0` would still admit a window's first take), and a `windowMs`
	 * that is not a positive finite number (one of `0` or less would reopen on
	 * every take, NaN never). Every adapter applies the same rule, a Redis
	 * script included.
	 *
	 * Clocks: a `now` behind `since` counts into the current window and opens
	 * none, so an earlier clock fails closed. A replica whose clock is ahead
	 * opens a window later than the others would, so for them it lasts longer.
	 * A `now` far in the future holds the budget spent until real time passes
	 * `since + windowMs`.
	 *
	 * Optional: a store without it keeps no rotation budget.
	 */
	takeRotation?(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly limit: number;
		readonly windowMs: number;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Gives back a rotation `takeRotation` took, for an attempt the upstream
	 * definitely did not perform. A rotation here is a refresh the upstream
	 * may have acted on, whether or not it issued a new refresh token. The grant must be `active`, at the caller's
	 * `version` (the one the take was made at), with `now` before `expiresAt`,
	 * and `rotations.since` must be `since`, the window the take counted into,
	 * with a `count` of at least one. Then, in one atomic step, `count - 1` and
	 * `version` bumped; nothing else touched. The bump makes it once per
	 * attempt: a second give-back at the same version is refused. A `now` or a
	 * `since` that is not a date is a `RangeError`.
	 *
	 * Optional for now, as `takeRotation` is, and the two become required
	 * together: a store without it keeps every rotation taken.
	 */
	refundRotation?(input: {
		readonly grantId: string;
		readonly expectedVersion: number;
		readonly since: Date;
		readonly now: Date;
	}): Promise<FederationGrantWrite>;

	/**
	 * Sets `lastUsedAt` on an `active` grant, never moving it back (retrievals
	 * may report out of order). No `version` bump; nothing for another state or
	 * an `at` that is not a date. Best effort: a store may reject when
	 * unreachable, and the caller carries on as if it had not.
	 */
	touch(grantId: string, at: Date): Promise<void>;

	/**
	 * The lock a refresh holds, keyed by grant. Waits up to `waitForMs` for a
	 * holder to release and never acquires after that (`0` is one attempt). No
	 * renewal: past `ttlMs` another caller may acquire it, and the first
	 * holder's `release` must leave that lock alone. `release` is idempotent.
	 *
	 * A rejection means the lock could not be asked for, not that it is held.
	 * `ttlMs` must be positive and finite and `waitForMs` non-negative, or it
	 * rejects with a `RangeError`: a NaN TTL compares as expired and would let
	 * two refreshes present one refresh token.
	 */
	acquireRefreshLock(
		grantId: string,
		options: { readonly ttlMs: number; readonly waitForMs: number },
	): Promise<FederationGrantLockResult>;
}

/** What a grant record knows of an intent: which one is current, and until when. */
export interface FederationGrantIntentPointer {
	/** Opaque to the store. Single-use, 256 bits of entropy behind it. */
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
 *   caller reads it as unreadable.
 * - `unreadable` — it does not authenticate under the current key ring, or
 *   against the record's authorization fields.
 * - `key_unavailable` — sealed under a key that is not in the ring: an outage,
 *   and the record is kept.
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
			 * How long the store waited before it took the lock, in milliseconds
			 * (`0` when taken at once). A duration, so it means the same on either
			 * clock, measured on a monotonic clock (a stepped system clock would
			 * report negative or hours). The holder counts every deadline from
			 * when it asked plus this, never from the acknowledgement, which would
			 * overstate what is left of the lock and could let a second holder in.
			 */
			readonly waitedMs: number;
			readonly release: () => Promise<void>;
	  }
	| { readonly acquired: false; readonly reason: "timeout" };

// ---------------------------------------------------------------------------
// ComponentMap slot
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationGrantStore?: FederationGrantStore;
	}
}
