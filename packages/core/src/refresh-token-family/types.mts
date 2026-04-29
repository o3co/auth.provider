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
 * Per A3 §5.1.
 */
export interface RefreshTokenFamily {
	readonly familyId: string;
	readonly activeJti: string;
	readonly revoked: boolean;
	readonly expiresAt: Date;
}

/**
 * Result of a `RefreshTokenFamilyStore.updateFamily` call.
 *
 * - `committed`: CAS commit succeeded. `family` is the newly persisted state.
 * - `not-found`: the family does not exist (or expired). The updater was
 *   NOT invoked.
 * - `aborted`: the updater returned null (caller signalled no-op). No state
 *   change.
 *
 * Per A3 §5.1.
 */
export type RefreshTokenFamilyUpdateResult =
	| { readonly outcome: "committed"; readonly family: RefreshTokenFamily }
	| { readonly outcome: "not-found" }
	| { readonly outcome: "aborted" };

/**
 * Storage primitive for refresh-token families.
 *
 * Theme A: this interface exposes only single-key atomic primitives. The
 * 4-outcome rotation ceremony (`rotated | replayed | revoked |
 * unknown_family`) is composed in the wrapper layer (`RefreshTokenRotation`),
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
	 * if `family.expiresAt <= now()` at call time.
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
	 * The updater is a pure function invoked with the current
	 * `RefreshTokenFamily` value. It MAY be invoked multiple times due to
	 * CAS retry; consumers MUST NOT rely on exactly-once invocation.
	 * Returning a new `RefreshTokenFamily` commits; returning `null` aborts.
	 *
	 * On CAS conflict (concurrent caller committed first), the adapter
	 * retries by re-reading state and re-invoking `updater`. Retry limit is
	 * implementation-defined but MUST be bounded; on exhaustion, throws
	 * `RefreshTokenStorageError({ reason: "conflict-exhausted" })`.
	 *
	 * Per A3 §5.1.
	 */
	updateFamily(
		familyId: string,
		updater: (current: RefreshTokenFamily) => RefreshTokenFamily | null,
	): Promise<RefreshTokenFamilyUpdateResult>;
}
