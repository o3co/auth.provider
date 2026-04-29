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
 * Inputs for the default RefreshTokenFamilyRevocation composition.
 * Per A3 §6.2.
 */
export interface DefaultRefreshTokenFamilyRevocationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}

/**
 * Default RefreshTokenFamilyRevocation composition.
 *
 * `revokeFamily` is idempotent: returning null from the updater on
 * already-revoked state classifies as "aborted" at the storage layer,
 * which the wrapper treats as success (the desired end-state is reached).
 * Same for not-found: the desired end-state (no live family) is already
 * present.
 *
 * `isFamilyRevoked` is read-only via findFamily; returns false if the
 * family does not exist or the `revoked` flag is false.
 *
 * Per A3 §6.2.
 */
export function createDefaultRefreshTokenFamilyRevocation(
	deps: DefaultRefreshTokenFamilyRevocationDeps,
): RefreshTokenFamilyRevocation {
	return {
		async revokeFamily(familyId) {
			await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
				if (current.revoked) return null; // already revoked, no-op
				return { ...current, revoked: true };
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
