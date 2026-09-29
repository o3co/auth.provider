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
 * A refresh-token family aggregate.
 *
 * `activeJti` is always a non-empty string: registered with the family,
 * replaced by rotation, and kept on revocation (the jti active when the family
 * died, for audit). `expiresAtMs` is epoch milliseconds rather than a `Date`,
 * which `Object.freeze` cannot protect from `setTime`. For a live family it is
 * the lifetime that caps its refresh tokens' `exp`; for a revoked one, how long
 * the revocation is remembered (`retention.mts`), since `isFamilyRevoked`
 * answers from the record.
 */
export interface RefreshTokenFamily {
	readonly familyId: string;
	readonly activeJti: string;
	readonly revoked: boolean;
	readonly expiresAtMs: number;
}

/**
 * What an updater tells the adapter to do, and what it wants reported back:
 *
 * - `{ action: "commit", family, reason? }`: persist `family`;
 * - `{ action: "abort", reason? }`: write nothing.
 *
 * `reason` is opaque and caller-defined: the adapter never stores or
 * interprets it, only echoes it on the matching
 * {@link RefreshTokenFamilyUpdateResult}. It lets a caller classify a write
 * inside the atomic operation, including a commit that is a rejection (a
 * replay revocation), which a closure variable cannot do since the updater may
 * run more than once. Keeping it opaque keeps the adapter a storage primitive.
 */
export type RefreshTokenFamilyUpdateDecision =
	| {
			readonly action: "commit";
			readonly family: RefreshTokenFamily;
			readonly reason?: string;
	  }
	| { readonly action: "abort"; readonly reason?: string };

/**
 * Result of a `RefreshTokenFamilyStore.updateFamily` call.
 *
 * - `committed`: the CAS commit succeeded; `family` is the persisted state.
 * - `not-found`: no family (or it expired); the updater was not invoked.
 * - `aborted`: the updater aborted; no state change.
 *
 * `reason` echoes, verbatim, the decision that settled the call, even after
 * CAS retries.
 */
export type RefreshTokenFamilyUpdateResult =
	| {
			readonly outcome: "committed";
			readonly family: RefreshTokenFamily;
			readonly reason?: string;
	  }
	| { readonly outcome: "not-found" }
	| { readonly outcome: "aborted"; readonly reason?: string };

/**
 * Storage primitive for refresh-token families: single-key atomic operations
 * only. The rotation ceremony's outcomes are classified by the wrapper
 * ({@link RefreshTokenFamilyRotation}), not by the adapter.
 */
export interface RefreshTokenFamilyStore {
	readonly kind: string;

	/**
	 * Atomically registers a new family.
	 *
	 * @throws RefreshTokenStorageError `duplicate-family` if the `familyId`
	 * exists in any state (an RNG collision or a bug); of N concurrent calls
	 * with one `familyId`, exactly one succeeds.
	 * @throws RefreshTokenStorageError `expired-at-issue` if
	 * `family.expiresAtMs <= now()`.
	 * @throws RangeError, recording nothing, if `family.expiresAtMs` is not a
	 * finite instant within the Date range (`isStorableExpiry`). A fractional
	 * value is valid; an adapter storing whole milliseconds rounds it up.
	 */
	registerFamily(family: RefreshTokenFamily): Promise<void>;

	/** Non-mutating lookup; `null` when no record exists or it has expired. */
	findFamily(familyId: string): Promise<RefreshTokenFamily | null>;

	/**
	 * Atomic read-modify-write of the family: read it, call `updater`, and on
	 * `commit` compare-and-swap with an adapter-internal version (not exposed on
	 * `RefreshTokenFamily`: a version field, an ETag, Redis WATCH...). On
	 * conflict, re-read and re-invoke up to a bounded limit, then throw
	 * `RefreshTokenStorageError({ reason: "conflict-exhausted" })`. `abort`
	 * writes nothing and is not retried. A missing family returns `not-found`
	 * without invoking the updater.
	 *
	 * Updater contract (normative):
	 * - pure and synchronous: it may run several times per call;
	 * - must not mutate its input (adapters may freeze it);
	 * - returns a {@link RefreshTokenFamilyUpdateDecision};
	 * - must not commit `expiresAtMs <= now()`: adapters throw
	 *   `RefreshTokenStorageError({ reason: "expired-at-issue" })`, as
	 *   `registerFamily` does;
	 * - a committed `expiresAtMs` outside the Date range is a `RangeError` with
	 *   nothing written; a fractional one may come back rounded up.
	 *
	 * The adapter echoes the settling decision's `reason` without validating or
	 * persisting it, and omits the key when there was none (absent and
	 * `undefined` differ to `in`, `Object.keys`, `toStrictEqual` and
	 * serialisation): use {@link withReason}, as both in-tree adapters do.
	 */
	updateFamily(
		familyId: string,
		updater: (current: RefreshTokenFamily) => RefreshTokenFamilyUpdateDecision,
	): Promise<RefreshTokenFamilyUpdateResult>;
}

/**
 * The rotation ceremony's outcomes.
 *
 * - `rotated`: `previousJti` was active and the CAS committed `newJti`.
 *   `cappedExpiresAtMs` is the committed family ceiling (the family TTL is set
 *   once and never extended). It is read back after the commit, and the Redis
 *   adapter reconstructs it after the round trip, so it may drift a few ms
 *   past the stored TTL: fine for detecting the cap, but a JWT `exp` derived
 *   from it needs a safety margin (see the Redis adapter's `updateFamily`).
 * - `replayed`: `previousJti` was not the active jti. The caller must reject
 *   and treat it as a replay-attack signal. `familyRevoked: true` means the
 *   implementation already revoked the family in the same atomic operation
 *   (RFC 6819 §5.2.2.3; a separate write leaves a window for a sibling to
 *   rotate); absent, the caller must revoke it itself (fail-closed).
 * - `revoked`: the family is revoked (also what a sibling sees after a
 *   replay). The caller must reject; a logout-cascade signal.
 * - `unknown_family`: no record. The grant handler applies
 *   `oauth.refreshToken.unknownFamilyPolicy`: `"reject"` answers
 *   `400 invalid_grant`, `"accept"` issues with a warning (for bounded
 *   migration windows only).
 *
 * The optional fields stay optional so implementations without them keep
 * compiling.
 */
export type RefreshTokenFamilyRotationOutcome =
	| { readonly outcome: "rotated"; readonly cappedExpiresAtMs?: number }
	| { readonly outcome: "replayed"; readonly familyRevoked?: boolean }
	| { readonly outcome: "revoked" }
	| { readonly outcome: "unknown_family" };

/**
 * Composes `RefreshTokenFamilyStore.updateFamily` into the rotation ceremony.
 * The default (`createRefreshTokenFamilyRotation`) ships as
 * `defaultRefreshTokenFamilyRotationModule`; replace the module for custom
 * policy (audit-emitting or grace-period rotation).
 */
export interface RefreshTokenFamilyRotation {
	/**
	 * Registers a new family at initial issue (not rotation), e.g. from the
	 * authorization_code grant, via `RefreshTokenFamilyStore.registerFamily`.
	 *
	 * @throws RefreshTokenStorageError `duplicate-family` if `familyId` exists,
	 * or `expired-at-issue` if `expiresAtMs <= now()`.
	 */
	register(newJti: string, familyId: string, expiresAtMs: number): Promise<void>;

	/**
	 * Runs the rotation ceremony. The outcome union is the whole contract for
	 * normal flow; only system errors throw (network failures,
	 * `RefreshTokenStorageError({ reason: "conflict-exhausted" })`).
	 *
	 * Replay (normative): an implementation returning `replayed` SHOULD already
	 * have revoked the family in the same atomic operation, and then MUST set
	 * `familyRevoked: true`; two writes let a concurrent sibling redeem the
	 * still-active token. One that cannot revoke atomically omits the flag, and
	 * the caller revokes separately.
	 */
	rotate(
		previousJti: string,
		newJti: string,
		familyId: string,
		expiresAtMs: number,
	): Promise<RefreshTokenFamilyRotationOutcome>;
}

/**
 * Family revocation: an idempotent revoke and a read-only check. Separate from
 * rotation because triggers, callers and outcomes differ (admin operation or
 * logout cascade vs. the authentication flow). The default
 * (`createRefreshTokenFamilyRevocation`) ships as
 * `defaultRefreshTokenFamilyRevocationModule`.
 */
export interface RefreshTokenFamilyRevocation {
	/**
	 * Marks a family revoked, idempotently: sets `revoked` on a live family,
	 * succeeds on a revoked one, and records a missing one as revoked (its
	 * record may have run out while an access token it minted is still live).
	 * The revoked record MUST be kept until the last access token the family
	 * could have minted stops being accepted, since `isFamilyRevoked` answers
	 * `false` without a record; the shipped implementation sizes that from the
	 * access-token maximum (`retention.mts`).
	 */
	revokeFamily(familyId: string): Promise<void>;

	/**
	 * Whether a family record exists with `revoked` set; `false` without a
	 * record. Hot path: called per request by token-validation routes.
	 */
	isFamilyRevoked(familyId: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// ComponentMap slots, declared by declaration merging so consumers opt in
// additively; the boot planner resolves them from module `provides`.
// Unnamespaced slot names are reserved for o3co packages: consumers augmenting
// ComponentMap MUST namespace their key (e.g. acme.refreshTokenStore).
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly refreshTokenFamilyStore?: RefreshTokenFamilyStore;
		readonly refreshTokenFamilyRotation?: RefreshTokenFamilyRotation;
		readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	}
}
