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
import type { RefreshTokenFamilyRevocation, RefreshTokenFamilyStore } from "./types.mjs";

/**
 * Inputs for the RefreshTokenFamilyRevocation composition.
 * Per A3 §6.2.
 */
export interface RefreshTokenFamilyRevocationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}

/**
 * RefreshTokenFamilyRevocation composition.
 *
 * `revokeFamily` is idempotent: aborting the updater on already-revoked
 * state classifies as "aborted" at the storage layer, which the wrapper
 * treats as success (the desired end-state is reached). Same for not-found:
 * the desired end-state (no live family) is already present.
 *
 * Note (#274): the refresh-grant replay path no longer routes through here —
 * `createRefreshTokenFamilyRotation` revokes inside the same compare-and-swap
 * that detects the replay. This wrapper remains the entry point for
 * revocations that are NOT a replay classification: admin operations, logout
 * cascade, and the caller's fail-closed fallback for a custom rotation
 * implementation that reports `replayed` without `familyRevoked: true`.
 *
 * `isFamilyRevoked` is read-only via findFamily; returns false if the
 * family does not exist or the `revoked` flag is false.
 *
 * Per A3 §6.2.
 */
export function createRefreshTokenFamilyRevocation(
	deps: RefreshTokenFamilyRevocationDeps,
): RefreshTokenFamilyRevocation {
	return {
		async revokeFamily(familyId) {
			await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
				if (current.revoked) return { action: "abort" }; // already revoked, no-op
				// Freeze the committed family mirroring rotation.mts (defence-in-depth).
				// Adapters also freeze returned families, but freezing here is the
				// declared updater convention so future wrapper code that reads the
				// returned family does not encounter a mutable handle.
				return { action: "commit", family: Object.freeze({ ...current, revoked: true }) };
			});
			// All three RefreshTokenFamilyUpdateResult outcomes are valid success
			// paths for an idempotent revoke:
			//   - committed: flipped revoked: false -> true
			//   - aborted: already revoked
			//   - not-found: already GC'd or never existed
		},

		async isFamilyRevoked(familyId) {
			const family = await deps.refreshTokenFamilyStore.findFamily(familyId);
			return family?.revoked ?? false;
		},
	};
}
