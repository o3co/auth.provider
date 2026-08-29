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
	readonly backchannelLogoutUri?: string;
	readonly backchannelLogoutSessionRequired?: boolean;
	readonly frontchannelLogoutUri?: string;
	readonly frontchannelLogoutSessionRequired?: boolean;
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
 * far out as the longest-lived credential the watermark has to refuse — which
 * is the longest-lived **refresh token**, not the access token, wherever the
 * composition forwards `subjectRevocation` to the refresh grant (`oauthModule`
 * does). Family revocation is the primary kill for refresh tokens and the
 * watermark is the backstop for the case family revocation did not complete, so
 * sizing the watermark to the access-token TTL retires the backstop minutes
 * after a cascade failure while the RT it exists to catch lives for days.
 */
export interface SubjectRevocation {
	readonly kind: string;
	revokeBefore(subject: string, before: Date, expiresAt: Date): Promise<void>;
	/** The watermark, or `null` when this subject has none in force. */
	revokedBefore(subject: string): Promise<Date | null>;
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
