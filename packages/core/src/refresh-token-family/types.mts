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
 * Refresh-token family aggregate value type.
 *
 * The single-active-jti-per-family invariant is encoded structurally:
 * `activeJti` is always a non-empty string. The aggregate is registered
 * atomically with its initial activeJti via `registerFamily` and remains
 * a string field for the family's lifetime; rotation updates the value
 * (via `updateFamily`); revocation does NOT clear it (a revoked family
 * retains the jti that was active when it was revoked, for audit purposes).
 *
 * `expiresAtMs` stores the expiry as a Unix epoch millisecond timestamp
 * (number). Using epoch-ms eliminates the Date mutation surface that
 * Object.freeze cannot defend against — a caller holding a reference to
 * a Date object could call setTime(0) and corrupt store state.
 *
 * Per A3 §5.1.
 */
export interface RefreshTokenFamily {
	readonly familyId: string;
	readonly activeJti: string;
	readonly revoked: boolean;
	readonly expiresAtMs: number;
}

/**
 * What an updater tells the adapter to do, and what it wants reported back.
 *
 * This replaces the earlier `RefreshTokenFamily | null` return (#274). `null`
 * conflated two unrelated things — "write nothing" and "the caller's
 * precondition failed" — so the only way to communicate *why* a call ended
 * was a closure-captured variable read after the fact. That worked while
 * every rejection also aborted the write. It stops working the moment a
 * rejection needs to COMMIT something: a committed replay-revocation and a
 * committed ordinary rotation are indistinguishable at the result, and the
 * closure cannot disambiguate them without the adapter promising exactly-once
 * updater invocation, which the CAS retry contract explicitly refuses to.
 *
 * So the decision is a third state rather than an overloaded `null`:
 *
 * - `{ action: "commit", family }` — persist `family`.
 * - `{ action: "commit", family, reason }` — persist `family`, and hand
 *   `reason` back to the caller so it can classify the write as something
 *   other than the happy path.
 * - `{ action: "abort", reason? }` — write nothing.
 *
 * `reason` is an **opaque, caller-defined** string that the adapter stores
 * nowhere and interprets never — it only echoes it on the matching
 * `RefreshTokenFamilyUpdateResult`. Keeping it opaque is what preserves A3
 * §5.1's rule that the adapter is a storage primitive and the rotation
 * ceremony is classified in the wrapper layer.
 *
 * Per A3 §5.1 + #274.
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
 * - `committed`: CAS commit succeeded. `family` is the newly persisted state.
 *   `reason` echoes the committing decision's `reason`, verbatim.
 * - `not-found`: the family does not exist (or expired). The updater was
 *   NOT invoked, so there is no `reason` to echo.
 * - `aborted`: the updater returned `{ action: "abort" }`. No state change.
 *   `reason` echoes that decision's `reason`, verbatim.
 *
 * When the adapter retried the CAS, the echoed `reason` belongs to the
 * **decision that actually settled the call** — the committing invocation, or
 * the aborting one. That is the property the closure-captured-variable
 * pattern could not guarantee.
 *
 * Per A3 §5.1 + #274.
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
 * Storage primitive for refresh-token families.
 *
 * Theme A: this interface exposes only single-key atomic primitives. The
 * 4-outcome rotation ceremony (`rotated | replayed | revoked |
 * unknown_family`) is composed in the wrapper layer (`RefreshTokenFamilyRotation`),
 * NOT classified by the adapter.
 *
 * Per A3 §5.1.
 */
export interface RefreshTokenFamilyStore {
	readonly kind: string;

	/**
	 * Atomically register a new refresh-token family.
	 *
	 * MUST throw `RefreshTokenStorageError({ reason: "duplicate-family" })`
	 * if a family with the same `familyId` already exists (regardless of
	 * revoke / TTL state — duplicate `familyId` indicates RNG collision or
	 * programming bug).
	 *
	 * MUST throw `RefreshTokenStorageError({ reason: "expired-at-issue" })`
	 * if `family.expiresAtMs <= now()` at call time.
	 *
	 * Concurrency contract: N concurrent calls with the same `familyId`
	 * MUST result in exactly one success and N-1 throws of
	 * `"duplicate-family"`.
	 *
	 * Per A3 §5.1.
	 */
	registerFamily(family: RefreshTokenFamily): Promise<void>;

	/**
	 * Non-mutating lookup of the family aggregate.
	 *
	 * Returns `null` if no record exists OR the record is expired (lazy GC).
	 *
	 * Per A3 §5.1.
	 */
	findFamily(familyId: string): Promise<RefreshTokenFamily | null>;

	/**
	 * Atomically read-modify-write the family aggregate.
	 *
	 * Adapter performs:
	 *   1. Read current family state (or null if non-existent).
	 *   2. Invoke `updater(current)`.
	 *   3. If the decision is `{ action: "commit", family }`, attempt atomic
	 *      CAS commit using an adapter-internal version token (NOT exposed in
	 *      RefreshTokenFamily — adapters may use a separate version field,
	 *      ETag, Redis WATCH, or any backend-native CAS primitive).
	 *   4. On CAS conflict, retry by re-reading state and re-invoking updater
	 *      up to a bounded retry limit; on exhaustion, throws
	 *      `RefreshTokenStorageError({ reason: "conflict-exhausted" })`.
	 *   5. If the decision is `{ action: "abort" }`, abort without state
	 *      change (no retry).
	 *
	 * Updater contract (NORMATIVE):
	 *   - Updater is invoked with the current RefreshTokenFamily value (NEVER
	 *     null — when the family does not exist, the adapter returns
	 *     `{ outcome: "not-found" }` directly without invoking the updater).
	 *   - Updater MUST be a pure function (no observable side effects, no
	 *     async I/O). Adapter MAY invoke updater multiple times due to CAS
	 *     retry; consumers MUST NOT rely on exactly-once invocation.
	 *   - Updater MUST NOT mutate the input RefreshTokenFamily (it is
	 *     `readonly` at the type level; runtime adapters MAY freeze it
	 *     additionally as defence-in-depth).
	 *   - Updater MUST return a {@link RefreshTokenFamilyUpdateDecision}:
	 *     `{ action: "commit", family, reason? }` or
	 *     `{ action: "abort", reason? }`. Returning a bare
	 *     `RefreshTokenFamily`, or `null`, is the pre-#274 shape and is no
	 *     longer accepted.
	 *   - A decision's `reason` is opaque to the adapter. The adapter MUST
	 *     echo the settling decision's `reason` on the returned result and
	 *     MUST NOT interpret, validate, or persist it. This is how a caller
	 *     classifies an outcome **inside** the same atomic operation — the
	 *     replacement for the pre-#274 closure-captured-variable pattern,
	 *     which could not describe a commit that is nevertheless a rejection
	 *     (see `createRefreshTokenFamilyRotation`, #274).
	 *   - Updater MUST NOT commit a RefreshTokenFamily whose `expiresAtMs` is
	 *     `<= now()`. Both adapters fail-closed by throwing
	 *     `RefreshTokenStorageError({ reason: "expired-at-issue" })` —
	 *     symmetric with `registerFamily` and prevents committing a
	 *     dead-on-arrival entry. Callers shrinking TTL during rotation
	 *     should compute the new `expiresAtMs` from a forward window.
	 *
	 * Return value:
	 *   - `{ outcome: "committed", family, reason? }` — CAS succeeded; family
	 *     is the newly-persisted state.
	 *   - `{ outcome: "not-found" }` — family did not exist; updater not
	 *     invoked.
	 *   - `{ outcome: "aborted", reason? }` — updater aborted; no state
	 *     change.
	 *
	 * Per A3 §5.1 + #274.
	 */
	updateFamily(
		familyId: string,
		updater: (current: RefreshTokenFamily) => RefreshTokenFamilyUpdateDecision,
	): Promise<RefreshTokenFamilyUpdateResult>;
}

/**
 * 4-outcome union for the rotation ceremony.
 *
 * - `rotated`: family exists, not revoked, previousJti matched the active
 *   jti, CAS commit succeeded with newJti. Optional `cappedExpiresAtMs`
 *   carries the actually-committed family ceiling (per IH-13: the rotation
 *   wrapper applies `Math.min(requestedExpiresAtMs, current.expiresAtMs)`
 *   so the family TTL is set ONCE at creation and never extended). The
 *   field is optional so existing test stubs that return `{ outcome:
 *   "rotated" }` without it continue to compile.
 *
 *   **Drift caveat**: `cappedExpiresAtMs` is read from
 *   `RefreshTokenFamilyUpdateResult.family.expiresAtMs` after a successful
 *   commit. The Redis adapter reconstructs that value as
 *   `Date.now() + newTtlMs` after the EXEC round-trip, so the returned
 *   epoch-ms drifts forward by single-digit milliseconds vs the value
 *   the updater computed. This drift is benign for cap-detection
 *   (`cappedExpiresAtMs < requestedExpiresAtMs` still indicates the cap
 *   fired), but the value is NOT a millisecond-precise mirror of the
 *   stored Redis TTL — Phase F consumers planning to align an issued
 *   JWT `exp` claim should subtract a safety margin or use `findFamily`
 *   for a fresher read. See `packages/redis/src/refresh-token-family.mts`
 *   `updateFamily` comment for the underlying mechanism.
 *
 * - `replayed`: family exists, not revoked, but previousJti did NOT match
 *   the active jti (e.g., previous jti was already rotated out). Caller
 *   MUST reject and treat as a replay-attack audit signal.
 *
 *   `familyRevoked: true` states that the implementation ALREADY revoked the
 *   family, in the same atomic store operation that detected the replay
 *   (#274). RFC 6819 §5.2.2.3 requires the whole family to die on replay, and
 *   doing it as a second write left a window in which a sibling holding the
 *   still-active token could rotate and receive tokens. An implementation
 *   that can revoke atomically SHOULD set this flag; the shipped
 *   `createRefreshTokenFamilyRotation` always does.
 *
 *   The field is **optional and fail-closed by absence**: a custom rotation
 *   implementation that predates #274 returns a bare `{ outcome: "replayed" }`,
 *   and a caller seeing no `familyRevoked: true` MUST perform the revocation
 *   itself rather than assume it happened. Optional rather than required so
 *   such implementations (and existing test stubs) keep compiling — the same
 *   compatibility choice made for `cappedExpiresAtMs`.
 *
 * - `revoked`: family exists but its `revoked` flag is set. Caller MUST
 *   reject and treat as a logout-cascade signal. Note that after #274 this
 *   is also what a sibling redemption sees once a replay has revoked the
 *   family.
 * - `unknown_family`: no family record matches `family_id`. The grant
 *   handler consults `oauth.refreshToken.unknownFamilyPolicy`:
 *   - `"reject"` (default, safe-by-default in v0.5.1+): returns
 *     `400 invalid_grant / "unknown_family"`.
 *   - `"accept"` (legacy migration mode only): falls through to issuance
 *     and emits a warn audit log. Intended for time-bounded migration
 *     windows when moving from v0.4.x in-memory family stores to Redis.
 *   The v0.4.x behavior was unconditional accept; v0.5.1+ defaults to
 *   reject per CC-2. Policy ownership lives in the oauth grant handler
 *   module, NOT this wrapper.
 *
 * Per A3 §5.2 + IH-13 (v0.5.1).
 */
export type RefreshTokenFamilyRotationOutcome =
	| { readonly outcome: "rotated"; readonly cappedExpiresAtMs?: number }
	| { readonly outcome: "replayed"; readonly familyRevoked?: boolean }
	| { readonly outcome: "revoked" }
	| { readonly outcome: "unknown_family" };

/**
 * Rotation ceremony wrapper. Composes `RefreshTokenFamilyStore.updateFamily`
 * into the 4-outcome union. The default impl
 * (`createRefreshTokenFamilyRotation`) is shipped as
 * `defaultRefreshTokenFamilyRotationModule`; consumers needing custom policy
 * (audit-emitting rotation, grace-period rotation, etc.) replace the
 * module with their own.
 *
 * Per A3 §5.2.
 */
export interface RefreshTokenFamilyRotation {
	/**
	 * Register a new refresh-token family at initial issue time (e.g., from
	 * the authorization_code grant handler).
	 *
	 * Delegates to `RefreshTokenFamilyStore.registerFamily(family)` after
	 * constructing a `RefreshTokenFamily` aggregate from the inputs.
	 *
	 * MUST throw `RefreshTokenStorageError({ reason: "duplicate-family" })`
	 * if `familyId` already exists. MUST throw
	 * `RefreshTokenStorageError({ reason: "expired-at-issue" })` if
	 * `expiresAtMs <= now()`.
	 *
	 * Use this for **initial issue**, not for rotation.
	 */
	register(newJti: string, familyId: string, expiresAtMs: number): Promise<void>;

	/**
	 * Compose the storage primitive into the 4-outcome rotation ceremony.
	 *
	 * Normal flow does NOT throw `RefreshTokenStorageError` or any other
	 * domain error — the discriminated outcome union IS the complete
	 * return contract. System errors (Redis network failure, CAS conflict
	 * exhaustion) propagate as native errors / `RefreshTokenStorageError(
	 * { reason: "conflict-exhausted" })`.
	 *
	 * Replay handling (NORMATIVE, #274): an implementation that returns
	 * `replayed` SHOULD have already revoked the family, in the same atomic
	 * store operation that detected the replay, and MUST then set
	 * `familyRevoked: true`. Detecting a replay and revoking the family as two
	 * separate writes leaves a window in which a concurrent sibling redeems
	 * the still-active token successfully — the defect this contract exists to
	 * prevent. An implementation that genuinely cannot revoke atomically omits
	 * the flag, and the caller falls back to revoking separately.
	 *
	 * Per A3 §5.2 + #274.
	 */
	rotate(
		previousJti: string,
		newJti: string,
		familyId: string,
		expiresAtMs: number,
	): Promise<RefreshTokenFamilyRotationOutcome>;
}

/**
 * Family revocation wrapper. Distinct from rotation per Theme B
 * (per `feedback_split_interface_unless_responsibility_intersects`):
 * different triggers (admin operation / logout cascade vs. normal
 * authentication flow), different callers, different expected outcomes.
 *
 * Idempotent revoke + read-only check. The default impl
 * (`createRefreshTokenFamilyRevocation`) ships as
 * `defaultRefreshTokenFamilyRevocationModule`.
 *
 * Per A3 §5.3.
 */
export interface RefreshTokenFamilyRevocation {
	/**
	 * Mark a refresh-token family as revoked. Idempotent:
	 *   - family exists, not revoked → set revoked: true, commit
	 *   - family exists, already revoked → no-op success
	 *   - family does not exist → no-op success (target was already GC'd or
	 *     never existed; admin tools / logout cascade should not fail in
	 *     that case)
	 *
	 * Per A3 §5.3.
	 */
	revokeFamily(familyId: string): Promise<void>;

	/**
	 * Read-only check whether a family is revoked.
	 *
	 * Returns `true` iff a family record exists AND its `revoked` flag is
	 * set. Returns `false` if the family does not exist OR is not revoked.
	 *
	 * Hot-path operation (called per request from token-validation routes).
	 *
	 * Per A3 §5.3.
	 */
	isFamilyRevoked(familyId: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A3 §5.5).
//
// All three A3 slots are declared via declaration-merging so consumers can
// opt into them additively. The slots are non-synthetic — boot planner
// resolves them from module `provides` at boot time per A2-beta §5.3.
//
// Slot-name reservation policy (A1 §5.5): unnamespaced names
// (refreshTokenFamilyStore, refreshTokenFamilyRotation, refreshTokenFamilyRevocation)
// are reserved for o3co packages. Consumers augmenting ComponentMap for
// their own use MUST namespace their key (e.g. acme.refreshTokenStore).
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly refreshTokenFamilyStore?: RefreshTokenFamilyStore;
		readonly refreshTokenFamilyRotation?: RefreshTokenFamilyRotation;
		readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenFamilyClient / RefreshTokenFamilyMultiClient /
// DisposableRefreshTokenFamilyClient backing-client interfaces relocated to
// @o3co/auth-provider-redis (v0.5.0 pre-tag interface review S3).
