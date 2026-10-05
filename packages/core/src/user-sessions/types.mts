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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { MfaEnrollmentWitness } from "../repositories/UserRepository.mjs";

// ---------------------------------------------------------------------------
// Value types (structurally immutable)
// ---------------------------------------------------------------------------

/**
 * OIDC-standard user claims durably attached to a session. Populated at
 * login; the authoritative source for /userinfo and id_token, independent of
 * the browser session.
 */
export interface UserSessionClaims {
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: ReadonlyArray<string>;
	readonly [customClaim: string]: unknown;
}

/**
 * A Relying Party that has completed a token exchange via this session.
 * Source data for OIDC Back-Channel / Front-Channel Logout fanout.
 */
export interface RegisteredRP {
	readonly clientId: string;
	readonly backchannelLogoutUri: string | undefined;
	readonly backchannelLogoutSessionRequired: boolean | undefined;
	readonly frontchannelLogoutUri: string | undefined;
	readonly frontchannelLogoutSessionRequired: boolean | undefined;
	readonly registeredAt: Date;
}

/**
 * Authenticated user session aggregate. Immutable after create, except for
 * what a verified second factor adds (`amr`, `authentication`) through the
 * optional step-up capability ({@link SupportsSecondFactorUpdate}).
 *
 * Time fields are `Date`, while low-level storage primitives (ChallengeStore,
 * RefreshTokenFamilyStore, ReplaySeenSet) use epoch-ms numbers. Convert
 * explicitly at the boundary (`new Date(ms)`, `date.getTime()`) so the two
 * encodings never alias one field.
 */
export interface UserSession {
	readonly sid: string;
	readonly sub: string;
	readonly authTime: Date;
	readonly createdAt: Date;
	readonly expiresAt: Date;
	readonly claims: UserSessionClaims;
	/**
	 * How the user authenticated: RFC 8176 values (`pwd`, `hwk`, `mfa`, `otp`,
	 * …) plus the deployment-defined `fed` for a federated login. Surfaced as
	 * the id_token `amr` claim and consulted by `/authorize` for `acr_values`.
	 * `undefined` when the login path recorded nothing.
	 *
	 * Holds only what this provider vouches for (the primary, a trusted
	 * upstream IdP's values, each verified second factor) in a session that
	 * says so in `authentication`; an older session is read through
	 * `vouchedAmr` (`./authentication.mts`), which splits it.
	 *
	 * A required key: stores copy the session field by field, and a copy that
	 * dropped `amr` would silently hide a step-up (`/authorize` answering
	 * `unmet_authentication_requirements`, the id_token without `amr`).
	 */
	readonly amr: readonly string[] | undefined;
	/**
	 * How the session was established; `undefined` for a session written before
	 * the key existed. Read it through `sessionAuthentication`, never directly.
	 * A required key like `amr`: a copy that dropped it would read every session
	 * as a pre-upgrade one, losing a trusted federation's values and a verified
	 * second factor.
	 */
	readonly authentication: SessionAuthentication | undefined;
	/**
	 * What the login's `User` said that a first binding is decided on (the MFA
	 * ADR's D12, D24), recorded when the session was established. Optional: a
	 * session without it — written before the key, or by a store that drops
	 * it — says nothing, and a reader decides what that means. A store
	 * round-trips it.
	 */
	readonly enrollmentFacts?: SessionEnrollmentFacts;
	/**
	 * The renewal nonce of the one cookie session this session is bound to
	 * (`./renewalNonce.mts`): recorded by `recordSecondFactor` with the
	 * escalation, and compared by admission with the cookie session's, which
	 * refuses any other. Absent: bound to no cookie session, read as before
	 * renewals existed. Optional, like `enrollmentFacts`: a store that drops
	 * it leaves its escalated sessions unbound, so a store with the step-up
	 * capability round-trips it.
	 */
	readonly renewalNonce?: string;
}

/**
 * What the login's `User` said that a first binding is decided on (the MFA
 * ADR's D12, D24), as core's primary builders derive it: never the `User`,
 * and never its address.
 */
export interface SessionEnrollmentFacts {
	/** The enrollment witness, as `readMfaEnrollmentWitness(user)` reads it. */
	readonly witness: MfaEnrollmentWitness;
	/** What `user.email` is: see {@link MailAddressFact}. */
	readonly mailAddress: MailAddressFact;
}

/**
 * What a `User`'s `email` is, as a first binding is decided on it: `none` —
 * absent, `null` or empty; `address` — one address `normaliseMailAddress`
 * reads; `unreadable` — anything else, which no proof can be sent to.
 */
export type MailAddressFact = "none" | "address" | "unreadable";

/**
 * How a session was established: the primary authentication, which
 * federation, what an untrusted upstream IdP asserted, and when a second
 * factor was last verified. Read through `sessionAuthentication`
 * (`./authentication.mts`), which answers the same shape for older sessions.
 * Every field is a required key, holding `undefined` where there is nothing
 * to say, so a copy names each one.
 */
export interface SessionAuthentication {
	/** How the session was established: `"pwd"` (`POST /session/login`), `"fed"` (a federation callback). */
	readonly primary: string;
	/**
	 * The federation, for `"fed"`: the name it is installed under — the key
	 * its callback resolved it by, whose `trustUpstreamAmr` applied. Equal to
	 * the adapter's `provider.name` for every provider a module registers,
	 * which boot refuses when named otherwise than its key; the federation
	 * index, logout and the federation-token store use `provider.name`.
	 */
	readonly federation: string | undefined;
	/** What an untrusted upstream IdP asserted: kept for the record, never stamped, never read for `acr`. */
	readonly upstreamAmr: readonly string[] | undefined;
	/** When a second factor was last verified, or bound, in this session. */
	readonly mfaAt: Date | undefined;
}

/**
 * Parameters for creating a new session. Federations are added afterwards via
 * `SessionFederationIndex.addFederation`.
 */
export interface CreateUserSessionInput {
	readonly sid: string;
	readonly sub: string;
	/**
	 * When the user authenticated. Must be a valid date at or after the epoch,
	 * no further ahead of the store's clock than `DEFAULT_CLOCK_SKEW_MS`: a
	 * `RangeError` otherwise, nothing recorded. Recorded no later than the
	 * store's clock (`recordableAuthTime`), as `authentication.mfaAt` is.
	 */
	readonly authTime: Date;
	readonly expiresAt: Date;
	readonly claims: UserSessionClaims;
	/**
	 * How the user authenticated (see {@link UserSession.amr}); `undefined` when
	 * the login path knows nothing of it. A required key, so a login path says
	 * what it knows.
	 */
	readonly amr: readonly string[] | undefined;
	/**
	 * How the session was established, composed with `amr` by
	 * `passwordSessionAuthentication` / `federatedSessionAuthentication`
	 * (`./authentication.mts`); `undefined` writes a session read as a
	 * pre-upgrade one. A required key. `mfaAt`, when present, must be a valid
	 * date at or after the epoch, no further ahead of the store's clock than
	 * `DEFAULT_CLOCK_SKEW_MS`: a `RangeError` otherwise, nothing recorded.
	 * Recorded no later than the store's clock (`recordableSessionAuthentication`).
	 */
	readonly authentication: SessionAuthentication | undefined;
	/**
	 * What the login's `User` said for a first binding (see
	 * {@link UserSession.enrollmentFacts}); absent writes a session that says
	 * nothing of it. A value `SessionEnrollmentFacts` does not admit is a
	 * `RangeError`, nothing recorded.
	 */
	readonly enrollmentFacts?: SessionEnrollmentFacts;
}

// ---------------------------------------------------------------------------
// Storage interfaces
// ---------------------------------------------------------------------------

/**
 * Sid-keyed store for the authenticated user session. Immutable after create;
 * a store may add the step-up capability ({@link SupportsSecondFactorUpdate}),
 * which writes a verified second factor into a live session and nothing else.
 *
 * `delete(sid)` is the global session-invalidation primitive. Sibling indexes
 * hold entries with a TTL synced to `session.expiresAt`; the orchestrator
 * calls `UserSessionStore.delete` LAST, so a failed sibling cleanup leaves the
 * session valid for retry.
 */
export interface UserSessionStore {
	readonly kind: string;
	/**
	 * Record a new session. Rejects when `sid` already has one, when
	 * `expiresAt` is already past, and — with a `RangeError`, recording
	 * nothing — when `expiresAt` is an Invalid Date, `authTime` or
	 * `authentication.mfaAt` is an Invalid Date, before the epoch or further
	 * ahead of the store's clock than `DEFAULT_CLOCK_SKEW_MS`, or
	 * `enrollmentFacts` is not what `SessionEnrollmentFacts` admits.
	 *
	 * `authTime` and `mfaAt` are each recorded no later than the store's
	 * clock: a store records what `recordableAuthTime` and
	 * `recordableSessionAuthentication` answer, never its input, so a session
	 * is never dated ahead of the clock that recorded it.
	 */
	create(input: CreateUserSessionInput): Promise<void>;
	get(sid: string): Promise<UserSession | null>;
	delete(sid: string): Promise<void>;
}

/**
 * A second factor verified in a session: the `amr` it adds (the factor's
 * values, and `mfa` when the factor adds it) and when it was verified.
 */
export interface SecondFactorEvent {
	readonly amr: readonly string[];
	readonly at: Date;
	/**
	 * The renewed cookie session's nonce (`LoginCompletion.renewSession`'s
	 * answer), recorded on the session in the same write, replacing an
	 * earlier one. Absent: the session's nonce is left as it is.
	 */
	readonly renewalNonce?: string;
	/**
	 * The renewal nonce the admitted cookie session held before its renewal;
	 * absent when it held none (a first step-up). The store records the event
	 * only while the session's nonce is this one — absent matching absent —
	 * in the same atomic write; otherwise it answers `null` and writes
	 * nothing, so of two completions started from one cookie session only the
	 * first is recorded.
	 */
	readonly expectedRenewalNonce?: string;
}

/**
 * The step-up capability: a store that can record a second factor verified
 * in a live session. Detected by method presence
 * ({@link supportsSecondFactorUpdate}); a custom store without it keeps
 * working, and a step-up asks for re-authentication instead. Both bundled
 * stores have it.
 */
export interface SupportsSecondFactorUpdate {
	/**
	 * Record that a second factor was verified in the live session `sid`, and
	 * answer the session as now stored.
	 *
	 * `amr` becomes what the session vouches for followed by `event.amr`, in
	 * insertion order, each value once. `mfaAt` becomes the later of the stored
	 * one and the event's, each clamped to the store's clock (so a value from a
	 * replica whose clock ran ahead comes back to it). `renewalNonce` becomes
	 * the event's, when it carries one, in the same write. Nothing else
	 * changes, `authTime` and the session's lifetime included. A session written before
	 * `authentication` existed is split first (`sessionAfterSecondFactor`), so
	 * an untrusted upstream IdP's value never becomes a vouched one.
	 *
	 * `null`, nothing written, when the session is gone, when its renewal
	 * nonce is not the event's `expectedRenewalNonce` (a completion another
	 * one overtook), or whenever `sessionAfterSecondFactor` answers `null`
	 * (`canRecordSecondFactor` is false): its primary cannot be told, or its
	 * `authentication` or `amr` is not in a shape the types admit. Where
	 * admission itself picks the second-factor authority to step a session up
	 * for `acr_values`, it reads the same condition and answers a new login
	 * (`reauthenticate`) instead; a requirement's own step-up is its to
	 * answer.
	 *
	 * A `RangeError` before anything is read, nothing written, for an event
	 * with no values, an empty value, a primary's marker (`pwd`, `fed`), only
	 * `mfa`, a time that is not a valid date at or after the epoch or is
	 * further ahead of the store's clock than `DEFAULT_CLOCK_SKEW_MS`, or a
	 * `renewalNonce` that is not one (`checkSecondFactorEvent`). A store outage rejects with the store's own
	 * error.
	 */
	recordSecondFactor(sid: string, event: SecondFactorEvent): Promise<UserSession | null>;
}

/**
 * Whether `value` has the step-up capability. `false` for `null` and
 * `undefined`, so an optional slot's value can be passed straight in.
 */
export function supportsSecondFactorUpdate(
	value: UserSessionStore | null | undefined,
): value is UserSessionStore & SupportsSecondFactorUpdate {
	const candidate = value as Partial<SupportsSecondFactorUpdate> | null | undefined;
	return typeof candidate?.recordSecondFactor === "function";
}

/**
 * Sid-keyed registry of Relying Parties that completed a token exchange via
 * this session: source data for OIDC Back-Channel / Front-Channel Logout.
 * Upsert per clientId; removed only with the whole session (`removeBySid`).
 *
 * Every `registerRP` MUST pass the session's `expiresAt`, which the adapter
 * uses as the entry's TTL. An Invalid Date (as `expiresAt` or the RP's
 * `registeredAt`) is a `RangeError`, and nothing is recorded.
 *
 * A `registerRP` that has resolved is visible to every `listRPs` on that sid
 * that starts after it, until the entry expires or `removeBySid`. A logout
 * reads the list after it ends the session, and a code exchange registers
 * the RP before it joins the session; a registry read from a replica, or
 * eventually consistent, can miss the RP and skip its logout. As with
 * {@link SupportsSessionEnd}, a backend that can lose a write it acknowledged
 * breaks it.
 */
export interface SessionRPRegistry {
	readonly kind: string;
	registerRP(sid: string, rp: RegisteredRP, expiresAt: Date): Promise<void>;
	listRPs(sid: string): Promise<ReadonlyArray<RegisteredRP>>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Sid-keyed index of refresh-token family ids: source data for cascade
 * revocation on logout. Append-only (idempotent on duplicates); removed only
 * with the whole session (`removeBySid`).
 *
 * Every `addFamilyId` MUST pass the session's `expiresAt`. An Invalid Date is
 * a `RangeError`, and nothing is recorded. An index may add the session-end
 * capability ({@link SupportsSessionEnd}), which keeps a family added while a
 * logout is under way from escaping it.
 */
export interface SessionFamilyIndex {
	readonly kind: string;
	addFamilyId(sid: string, familyId: string, expiresAt: Date): Promise<void>;
	listFamilyIds(sid: string): Promise<ReadonlyArray<string>>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * The session-end capability: a session's end, marked in the index, and an
 * add that refuses once it is. Detected by method presence
 * ({@link supportsSessionEnd}); an index without it keeps working. Both
 * bundled indexes have it, the Redis one when it is told where to keep the
 * mark and its client can write it.
 *
 * For an `addFamilyIdUnlessEnded` and an `endSession` on the same sid, either
 * the end's listing includes the family, or the add answers `"ended"`. When
 * the add answers `"ended"`, the family it wrote may stay unlisted until
 * `expiresAt`; the caller issues nothing for it.
 *
 * This holds while the store's reads and writes are linearizable, and its
 * reads are served by the primary: each sees every write completed before
 * it began. A backend that can lose a write it acknowledged, as Redis can
 * when a failover promotes a replica the write had not reached, or that
 * answers a read from a replica, breaks it. The guarantee holds for
 * operations inside the session's life on every clock involved; the mark
 * lasts the life plus the clock-skew allowance (`DEFAULT_CLOCK_SKEW_MS`), and
 * an add that finds `expiresAt` passed answers `"ended"`.
 *
 * Both calls MUST pass the session's `expiresAt`. `removeBySid` keeps the
 * mark. An Invalid Date is a `RangeError`, and nothing is recorded.
 */
export interface SupportsSessionEnd {
	/**
	 * Mark the session ended, and answer its families. The mark is written
	 * even once `expiresAt` has passed, until the allowance after it has too.
	 * Idempotent: a retry marks it again and answers the families again.
	 */
	endSession(sid: string, expiresAt: Date): Promise<ReadonlyArray<string>>;
	/**
	 * Add the family unless the session is marked ended: `"added"`, or
	 * `"ended"`. An `expiresAt` already past answers `"ended"`, and records
	 * nothing; one that passes before the add has read the mark answers
	 * `"ended"` too.
	 */
	addFamilyIdUnlessEnded(
		sid: string,
		familyId: string,
		expiresAt: Date,
	): Promise<"added" | "ended">;
}

/**
 * Both methods, or neither: an index with one of them is halfway through an
 * upgrade. `false` for `null` and `undefined`, so an optional slot's value can
 * be passed straight in.
 */
export function supportsSessionEnd(
	value: SessionFamilyIndex | null | undefined,
): value is SessionFamilyIndex & SupportsSessionEnd {
	const candidate = value as Partial<SupportsSessionEnd> | null | undefined;
	return (
		typeof candidate?.endSession === "function" &&
		typeof candidate?.addFamilyIdUnlessEnded === "function"
	);
}

/**
 * Sid-keyed index of upstream federation names that authenticated this
 * session: source data for cascade federation logout and for federation
 * token route gating.
 *
 * `listFederations(sid)` MUST return names in insertion order (oldest
 * first): `routes/logout.mts` picks the first for the post-logout redirect.
 * Append-only (idempotent on duplicates), with per-federation removal on
 * federation logout and full cleanup via `removeBySid`.
 *
 * Every `addFederation` MUST pass the session's `expiresAt`. An Invalid Date
 * is a `RangeError`, and nothing is recorded.
 */
export interface SessionFederationIndex {
	readonly kind: string;
	addFederation(sid: string, federationName: string, expiresAt: Date): Promise<void>;
	listFederations(sid: string): Promise<ReadonlyArray<string>>;
	removeFederation(sid: string, federationName: string): Promise<void>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Subject-keyed index of a principal's session ids: answers "what sessions
 * does this subject have?", which a credential change asks in order to end
 * every session without knowing a sid. `revokeAllForSubject` enumerates it.
 *
 * Append-only per (subject, sid), idempotent. `removeSid` removes one
 * session, leaving the subject's others.
 *
 * Every `addSid` MUST pass the session's `expiresAt`, so an abandoned session
 * ages out rather than accumulating against a long-lived user. An Invalid
 * Date is a `RangeError`, and nothing is recorded.
 */
export interface SubjectSessionIndex {
	readonly kind: string;
	addSid(subject: string, sid: string, expiresAt: Date): Promise<void>;
	listSids(subject: string): Promise<ReadonlyArray<string>>;
	/** Remove one session from the subject's set, leaving the others. */
	removeSid(subject: string, sid: string): Promise<void>;
	/** Remove the whole set — the subject has no live sessions left. */
	removeBySubject(subject: string): Promise<void>;
}

/**
 * The declared-absence policy for both subject-level revocation slots
 * ({@link SubjectRevocation}, {@link SubjectSessionIndex}): leaving them
 * unfilled must be a stated decision at boot, since without them `verifyJwt`
 * skips the watermark check, the refresh-redemption gate is inert and
 * `revokeAllForSubject` reports `unavailable`.
 *
 * One policy for both keys: they are one capability (the index enumerates
 * what to cascade, the watermark refuses what the cascade missed), and the
 * guard compares policies per key, so a shared constant keeps the boot
 * error's advice independent of which module tripped it.
 */
export const SUBJECT_REVOCATION_ABSENCE_POLICY = {
	configKey: ["oauth", "revocation", "subject"],
	absentValue: "unsupported",
	hint:
		"Without these a credential change cannot invalidate what was already issued: a " +
		"password reset leaves every existing session and access token working until it " +
		'expires. Wire both (`adapters.userSessionStores = "redis"` in the standalone ' +
		"template, or core's memorySessionStoresModule for a single-process deployment), " +
		'or declare `"unsupported"` to state that this deployment has no subject-level ' +
		"revocation. Refresh-token family revocation runs off the family store and is " +
		"unaffected either way.",
} as const;

/**
 * Per-subject not-before watermark for issued access tokens: a credential
 * change must invalidate outstanding tokens whose jtis are not enumerable, so
 * the watermark names the moment before which none count.
 *
 * Compared inclusively against `iat`, and against `auth_time` when a token
 * carries one (either at or before the watermark is revoked;
 * `claimCoveredByRevocationBoundary`): `iat` is second-truncated and replica
 * clocks differ, so a token minted just before the reset often shares the
 * watermark's second. Killing one minted just after costs a retry; letting
 * one from just before survive is the vulnerability this closes.
 *
 * `revokeBefore`'s `expiresAt` MUST reach at least as far as the
 * longest-lived credential the watermark must refuse, since it is the
 * backstop when family revocation did not complete. That includes an access
 * token outliving its refresh token and token exchange's
 * `oauth.accessToken.maxExpiresIn`; `resolveSubjectRevocationHorizonMs`
 * computes it. Adapters raise the stored expiry to the grants retention
 * floor whenever a write advances the grants boundary; nothing does so for a
 * sessions-only stamp.
 */
export interface SubjectRevocation {
	readonly kind: string;
	/**
	 * End everything for this subject: sessions, this provider's own tokens,
	 * and the subject's federation grants. Advances both boundaries, so a Store
	 * that never calls the sessions-only variant behaves as one watermark did.
	 * Keeping grants takes the deliberate call on
	 * {@link SupportsSessionsOnlyRevocation}.
	 *
	 * A `before` later than the store's clock plus `DEFAULT_CLOCK_SKEW_MS` is
	 * recorded as that clock plus the skew, by the rule
	 * `clampSubjectRevocationBoundary` states, with the clock read in the same
	 * atomic step as the write. It is never refused: a refusal would leave every
	 * token already issued alive. Such a boundary comes from a replica whose
	 * clock runs outside the tolerance; what that replica minted past the clamp
	 * is not covered, and the store's warn line is the signal. One behind the
	 * store's clock is recorded as given. A `RangeError`, nothing
	 * written, for a `before` or `expiresAt` that is not a `Date` with a finite
	 * time (`checkSubjectRevocationInstant`).
	 */
	revokeBefore(subject: string, before: Date, expiresAt: Date): Promise<void>;
	/** The sessions watermark, or `null` when this subject has none in force. */
	revokedBefore(subject: string): Promise<Date | null>;
}

/**
 * The second boundary: sessions and grants, separately. A password change
 * need not end every delegation (each agent and paused job would need a new
 * login, grant, consent and upstream authorization); an explicit revocation
 * does. See the federation-grants ADR.
 *
 * Both boundaries are fields of one record, advanced by one atomic,
 * monotonic write. With two writes, a session that should be dead could
 * consent between them, and that consent would escape the grants backstop
 * for good.
 *
 * Detected by method presence, so older adapters keep working where there
 * are no grants. With federation grants enabled boot requires it: method
 * presence cannot enforce the retention the backstop depends on.
 */
export interface SupportsSessionsOnlyRevocation {
	/**
	 * Advance the sessions boundary alone, leaving the grants boundary exactly
	 * as it was — including absent. It is never a way back: a grant an earlier
	 * revocation ended stays ended. Its `before` is clamped, and its
	 * arguments checked, as {@link SubjectRevocation.revokeBefore}'s are.
	 */
	revokeSessionsBefore(subject: string, before: Date, expiresAt: Date): Promise<void>;
	/** The grants watermark, or `null` when this subject has none in force. */
	grantsRevokedBefore(subject: string): Promise<Date | null>;
}

/**
 * Both methods, or neither. One of the two is an adapter halfway through an
 * upgrade, and reading its grants boundary would answer `null` — "nothing was
 * revoked" — for a subject whose grants a revocation had ended.
 */
export function supportsSessionsOnlyRevocation(
	value: SubjectRevocation,
): value is SubjectRevocation & SupportsSessionsOnlyRevocation {
	const candidate = value as Partial<SupportsSessionsOnlyRevocation> | null | undefined;
	return (
		typeof candidate?.revokeSessionsBefore === "function" &&
		typeof candidate?.grantsRevokedBefore === "function"
	);
}

// ---------------------------------------------------------------------------
// AdapterFactory aliases
// ---------------------------------------------------------------------------

export type UserSessionStoreFactory = AdapterFactory<UserSessionStore>;
export type SessionRPRegistryFactory = AdapterFactory<SessionRPRegistry>;
export type SessionFamilyIndexFactory = AdapterFactory<SessionFamilyIndex>;
export type SessionFederationIndexFactory = AdapterFactory<SessionFederationIndex>;
export type SubjectSessionIndexFactory = AdapterFactory<SubjectSessionIndex>;
export type SubjectRevocationFactory = AdapterFactory<SubjectRevocation>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (all slots optional)
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly userSessionStore?: UserSessionStore;
		readonly sessionRPRegistry?: SessionRPRegistry;
		readonly sessionFamilyIndex?: SessionFamilyIndex;
		readonly sessionFederationIndex?: SessionFederationIndex;
		readonly subjectSessionIndex?: SubjectSessionIndex;
		readonly subjectRevocation?: SubjectRevocation;
	}
}
