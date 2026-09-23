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

// ---------------------------------------------------------------------------
// Value types (Theme D: structurally immutable)
// ---------------------------------------------------------------------------

/**
 * OIDC-standard user claims durably attached to a session. Populated at
 * login. Used as the authoritative source for /userinfo and id_token;
 * independent of the browser session. Per A4 §5.1.
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
 * Source data for OIDC Back-Channel / Front-Channel Logout fanout. Per A4 §5.2.
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
 * Authenticated user session aggregate. Post-create immutable at v0.5.0
 * (claims update deferred post-publish). Per A4 §5.1.
 *
 * Expiry encoding: `expiresAt: Date` (not `expiresAtMs: number`) is intentional
 * for A4 aggregates. Per A3 §5.1: low-level storage primitives (A3:
 * ChallengeStore, RefreshTokenFamilyStore, ReplaySeenSet) use epoch-ms
 * `number` to eliminate Date mutation surface. A4 higher-level aggregates use
 * `Date` for ergonomics at the application layer. Callers bridging A3 and A4
 * convert explicitly at the boundary (`new Date(epochMs)` to lift, or
 * `someDate.getTime()` to lower) so the two encodings never alias the same
 * field. This is a deliberate two-tier design, not an inconsistency.
 */
export interface UserSession {
	readonly sid: string;
	readonly sub: string;
	readonly authTime: Date;
	readonly createdAt: Date;
	readonly expiresAt: Date;
	readonly claims: UserSessionClaims;
	/**
	 * #481: how the user authenticated — RFC 8176 values (`pwd`, `hwk`,
	 * `mfa`, `otp`, …) plus the deployment-defined `fed` for a federated
	 * login. Surfaced as the id_token `amr` claim and consulted by
	 * `/authorize` for `acr_values`. `undefined` when the login path recorded
	 * nothing (a session written before #481).
	 *
	 * A required key (#626): both stores copy the session field by field, and
	 * a copy that forgot `amr` would hide the step-up the user performed —
	 * every `acr_values` request asking them to sign in again — without an
	 * error. On the input, it makes a login path say what it knows.
	 */
	readonly amr: readonly string[] | undefined;
}

/**
 * Parameters for creating a new session. `federations` field DELETED vs
 * v0.4.x — federations are added separately via
 * `SessionFederationIndex.addFederation` after session create. Per A4 §5.1.
 *
 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
 * for rationale.
 */
export interface CreateUserSessionInput {
	readonly sid: string;
	readonly sub: string;
	readonly authTime: Date;
	readonly expiresAt: Date;
	readonly claims: UserSessionClaims;
	/**
	 * #481: how the user authenticated — RFC 8176 values (`pwd`, `hwk`,
	 * `mfa`, `otp`, …) plus the deployment-defined `fed` for a federated
	 * login. Surfaced as the id_token `amr` claim and consulted by
	 * `/authorize` for `acr_values`. `undefined` when the login path recorded
	 * nothing (a session written before #481).
	 *
	 * A required key (#626): both stores copy the session field by field, and
	 * a copy that forgot `amr` would hide the step-up the user performed —
	 * every `acr_values` request asking them to sign in again — without an
	 * error. On the input, it makes a login path say what it knows.
	 */
	readonly amr: readonly string[] | undefined;
}

// ---------------------------------------------------------------------------
// Storage interfaces (Theme B: 4-way split)
// ---------------------------------------------------------------------------

/**
 * Sid-keyed store for the authenticated user session. Post-create immutable
 * at v0.5.0 (claims update deferred post-publish). Per A4 §5.1.
 *
 * Cascade semantics: `delete(sid)` is the global session-invalidation
 * primitive. Sibling reverse-index stores hold orphan entries naturally
 * cleaned up via TTL synced to `session.expiresAt` at write time; the
 * orchestrator (route handler) calls `UserSessionStore.delete` LAST so any
 * failure in upstream sibling cleanup leaves the session valid for retry.
 * See A4 §6 cascade orchestration.
 */
export interface UserSessionStore {
	readonly kind: string;
	create(input: CreateUserSessionInput): Promise<void>;
	get(sid: string): Promise<UserSession | null>;
	delete(sid: string): Promise<void>;
}

/**
 * Sid-keyed registry of Relying Parties (RPs) that have completed a token
 * exchange via this session. Source data for OIDC Back-Channel /
 * Front-Channel Logout fanout. Per A4 §5.2.
 *
 * Mutability: append/upsert (per-clientId dedup); cleanup via removeBySid.
 * Per-RP removal is intentionally not exposed — RPs are removed only when
 * the entire session terminates.
 *
 * TTL contract: every `registerRP` MUST be called with the session's
 * `expiresAt`; the adapter writes the storage entry with TTL synced to
 * `expiresAt`.
 */
export interface SessionRPRegistry {
	readonly kind: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	registerRP(sid: string, rp: RegisteredRP, expiresAt: Date): Promise<void>;
	listRPs(sid: string): Promise<ReadonlyArray<RegisteredRP>>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Sid-keyed index of refresh-token family ids. Source data for cascade
 * revocation in the logout flow (consumes A3's RefreshTokenFamilyRevocation).
 * Per A4 §5.3.
 *
 * Mutability: append-only (idempotent on duplicate familyId); cleanup via
 * removeBySid. Per-family removal is not exposed.
 *
 * TTL contract: every `addFamilyId` MUST be called with the session's
 * `expiresAt`.
 */
export interface SessionFamilyIndex {
	readonly kind: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	addFamilyId(sid: string, familyId: string, expiresAt: Date): Promise<void>;
	listFamilyIds(sid: string): Promise<ReadonlyArray<string>>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Sid-keyed index of upstream federation provider names that have
 * authenticated this session. Per A4 §5.4.
 *
 * Source data for: (a) cascade federation logout; (b) federation token
 * route gating (`isFederationLinked(sid, name)` semantics).
 *
 * Ordering contract (load-bearing): `listFederations(sid)` MUST return
 * federation names in INSERTION order (oldest first). `routes/logout.mts`
 * consumes the first element to choose the IdP for post-logout redirect.
 *
 * Mutability: append-only (idempotent on duplicate name) + per-federation
 * removal (`removeFederation(sid, name)`) for federation logout completion +
 * full cleanup via `removeBySid`.
 *
 * TTL contract: every `addFederation` MUST be called with the session's
 * `expiresAt`.
 */
export interface SessionFederationIndex {
	readonly kind: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	addFederation(sid: string, federationName: string, expiresAt: Date): Promise<void>;
	listFederations(sid: string): Promise<ReadonlyArray<string>>;
	removeFederation(sid: string, federationName: string): Promise<void>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Subject-keyed index of the session ids belonging to one principal (#296).
 *
 * Every other index here is keyed by `sid` — they answer "what does this
 * session own?". This one answers the inverse, "what sessions does this
 * subject have?", which is the question a credential change asks: the Store
 * has just written a new password and every session established with the old
 * one has to go, without the caller knowing a single sid.
 *
 * `UserSessionStore` cannot answer it — it is `create` / `get(sid)` /
 * `delete(sid)` — so without this index `revokeAllForSubject` has nothing to
 * enumerate.
 *
 * Mutability: append-only per (subject, sid), idempotent on duplicates.
 * Per-member removal (`removeSid`) is exposed because a single session ending
 * must not erase the subject's other sessions — unlike the sid-keyed indexes,
 * where the whole key dies with the session.
 *
 * TTL contract: every `addSid` MUST be called with the session's `expiresAt`,
 * so an abandoned session ages out of the index rather than accumulating
 * against a long-lived user.
 */
export interface SubjectSessionIndex {
	readonly kind: string;
	/**
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	addSid(subject: string, sid: string, expiresAt: Date): Promise<void>;
	listSids(subject: string): Promise<ReadonlyArray<string>>;
	/** Remove one session from the subject's set, leaving the others. */
	removeSid(subject: string, sid: string): Promise<void>;
	/** Remove the whole set — the subject has no live sessions left. */
	removeBySubject(subject: string): Promise<void>;
}

/**
 * Per-subject not-before watermark for issued access tokens (#296).
 *
 * A credential change has to invalidate outstanding access tokens, and
 * `AccessTokenDenylist` cannot express that: it is `add(jti)` / `has(jti)`,
 * and the jtis a subject currently holds are not enumerable anywhere. A
 * watermark inverts the problem — instead of naming every token, it names the
 * moment before which none of them count.
 *
 * The comparison is against the token's `iat`, and it is deliberately
 * inclusive (`iat <= watermark` is revoked). `iat` is second-truncated
 * (`generateToken` floors `Date.now() / 1000`) and a multi-replica deployment
 * has independent clocks, so a token minted a few hundred milliseconds before
 * the reset routinely lands in the same second as the watermark. Killing a
 * token minted just *after* the reset costs the client one retry; letting one
 * from just *before* survive is the vulnerability this exists to close.
 *
 * TTL contract: `revokeBefore` MUST be called with an `expiresAt` at least as
 * far out as the longest-lived credential the watermark has to refuse.
 * Family revocation is the primary kill for refresh tokens and the watermark
 * is the backstop for the case family revocation did not complete, so a
 * watermark that lapses first takes the backstop with it.
 *
 * **Amended in slice 5** — this used to say "the longest-lived refresh token,
 * **not** the access token", and that was wrong in two ways. A deployment is
 * free to configure an access token that outlives its refresh token, and
 * token exchange may mint one up to `oauth.accessToken.maxExpiresIn` rather
 * than the default. `resolveSubjectRevocationHorizonMs` is the reader that
 * gets this right: the session, the refresh token, and the access-token
 * **maximum**, each extended by the tolerance it is actually accepted with.
 *
 * Adapters raise the stored expiry to the grants retention floor whenever a
 * write advances the grants boundary, so a caller that under-sizes this
 * cannot leave a grant outliving the boundary that revoked it. Nothing raises
 * it for a sessions-only stamp, which is why the horizon above exists.
 */
/**
 * The declared-absence policy for **both** subject-level revocation slots
 * (#406) — the one silent no-op #363 did not close.
 *
 * #363 gave `auditSink` and `accessTokenDenylist` policies so an unfilled
 * optional slot has to be a stated decision at boot, and its own doc cites "a
 * subject-revocation watermark nothing consulted (#322)" as motivation.
 * {@link SubjectRevocation} and {@link SubjectSessionIndex} did not get one,
 * and the consequence reached every shape this repository ships: a scaffolded
 * deployment got `subjectRevocation: undefined`, so `verifyJwt` skipped the
 * watermark check, the #376 refresh-redemption gate was inert, and
 * `revokeAllForSubject` reported `unavailable` — with no boot-time signal in
 * either direction.
 *
 * **One policy for two keys, on purpose.** They are two components but one
 * capability: subject-level revocation needs the index to enumerate what to
 * cascade and the watermark to refuse what the cascade missed. A deployment
 * that has neither has one thing to say, not two, and #321's adapters fill
 * them together for the same reason. The declared-absence guard compares
 * policies per key, so sharing one constant across both is exactly what keeps
 * the boot error's advice from depending on which module tripped it.
 */
export const SUBJECT_REVOCATION_ABSENCE_POLICY = {
	configKey: ["oauth", "revocation", "subject"],
	absentValue: "unsupported",
	hint:
		"Without these a credential change cannot invalidate what was already issued: a " +
		"password reset leaves every existing session and access token working until it " +
		'expires. Wire both (`userSessionStores.adapter = "redis"` in the standalone ' +
		"template, or core's memorySessionStoresModule for a single-process deployment), " +
		'or declare `"unsupported"` to state that this deployment has no subject-level ' +
		"revocation. Refresh-token family revocation runs off the family store and is " +
		"unaffected either way.",
} as const;

export interface SubjectRevocation {
	readonly kind: string;
	/**
	 * End everything for this subject: sessions, this provider's own tokens,
	 * and — since #593 — the subject's federation grants.
	 *
	 * It advances **both** boundaries of D13, which is what makes a Store that
	 * upgrades without touching this call site behave exactly as one watermark
	 * always did. Keeping grants is the narrower, newer operation, and it takes
	 * the deliberate call on {@link SupportsSessionsOnlyRevocation}.
	 */
	revokeBefore(subject: string, before: Date, expiresAt: Date): Promise<void>;
	/** The sessions watermark, or `null` when this subject has none in force. */
	revokedBefore(subject: string): Promise<Date | null>;
}

/**
 * The second boundary (#593, D13): sessions and grants, separately.
 *
 * A password change and "revoke everything" are different events. Ending every
 * delegation on every password change puts the price in the wrong place — each
 * agent and each paused job then needs a new login, a new grant, a new consent
 * and a new upstream authorization — and the industry does not do it either:
 * in Entra's own table a confidential client's token survives a password
 * change, and only an explicit revocation ends every class.
 *
 * The two boundaries are two fields of **one record**, advanced by one atomic,
 * monotonic write. Two writes would open a window between them: with the
 * grants boundary written and the sessions boundary still to come, a session
 * that should already be dead could consent, and that consent would be dated
 * after the grants boundary and escape the backstop for good.
 *
 * A capability, detected by method presence like the others, so an adapter
 * written before #593 keeps working in a deployment that has no grants. With
 * federation grants enabled it is required, and boot refuses an adapter
 * without it — method presence can only change which watermark is read; it
 * cannot enforce the retention the backstop depends on.
 */
export interface SupportsSessionsOnlyRevocation {
	/**
	 * Advance the sessions boundary alone, leaving the grants boundary exactly
	 * as it was — including absent. It is never a way back: a grant an earlier
	 * revocation ended stays ended.
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
// AdapterFactory aliases (Theme C: composition-root, throw-on-duplicate)
// ---------------------------------------------------------------------------

export type UserSessionStoreFactory = AdapterFactory<UserSessionStore>;
export type SessionRPRegistryFactory = AdapterFactory<SessionRPRegistry>;
export type SessionFamilyIndexFactory = AdapterFactory<SessionFamilyIndex>;
export type SessionFederationIndexFactory = AdapterFactory<SessionFederationIndex>;
export type SubjectSessionIndexFactory = AdapterFactory<SubjectSessionIndex>;
export type SubjectRevocationFactory = AdapterFactory<SubjectRevocation>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (4 slots, all optional)
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

// ---------------------------------------------------------------------------
// Backing client interfaces (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

// UserSessionStoreClient / SessionRPRegistryClient (+Multi) /
// SessionSidSortedSetClient (+Multi) backing-client interfaces relocated to
// @o3co/auth-provider-redis (v0.5.0 pre-tag interface review S3).
