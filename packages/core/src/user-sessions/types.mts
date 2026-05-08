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
 * `Date` for ergonomics at the application layer. Callers bridging A3/A4
 * convert at the boundary (e.g. `new Date(family.expiresAtMs)` in cascade-
 * logout). This is a deliberate two-tier design, not an inconsistency.
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

// ---------------------------------------------------------------------------
// AdapterFactory aliases (Theme C: composition-root, throw-on-duplicate)
// ---------------------------------------------------------------------------

export type UserSessionStoreFactory = AdapterFactory<UserSessionStore>;
export type SessionRPRegistryFactory = AdapterFactory<SessionRPRegistry>;
export type SessionFamilyIndexFactory = AdapterFactory<SessionFamilyIndex>;
export type SessionFederationIndexFactory = AdapterFactory<SessionFederationIndex>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (4 slots, all optional)
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly userSessionStore?: UserSessionStore;
		readonly sessionRPRegistry?: SessionRPRegistry;
		readonly sessionFamilyIndex?: SessionFamilyIndex;
		readonly sessionFederationIndex?: SessionFederationIndex;
	}
}

// ---------------------------------------------------------------------------
// Backing client interfaces (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

// UserSessionStoreClient / SessionRPRegistryClient (+Multi) /
// SessionSidSortedSetClient (+Multi) backing-client interfaces relocated to
// @o3co/auth-provider-redis (v0.5.0 pre-tag interface review S3).
