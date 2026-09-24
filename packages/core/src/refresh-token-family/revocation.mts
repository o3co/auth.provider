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
import { RefreshTokenStorageError } from "./errors.mjs";
import { assertAccessTokenHorizonMs, revokedFamilyExpiresAtMs } from "./retention.mjs";
import type { RefreshTokenFamilyRevocation, RefreshTokenFamilyStore } from "./types.mjs";

/**
 * Inputs for the RefreshTokenFamilyRevocation composition.
 * Per A3 §6.2.
 */
export interface RefreshTokenFamilyRevocationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
	/**
	 * The longest an access token carrying a family's id can live, in
	 * milliseconds — `resolveFamilyAccessTokenHorizonMs(config)`, which is
	 * what `defaultRefreshTokenFamilyRevocationModule` passes. A revoked
	 * family's record is kept until the last such token stops being accepted
	 * (`retention.mts`). Required, not defaulted: without it a revocation is
	 * forgotten while the tokens it revoked still verify.
	 */
	readonly accessTokenHorizonMs: number;
}

/**
 * The `activeJti` of a record written for a family that was revoked after its
 * own record had run out. The field is a non-empty string by the aggregate's
 * invariant; no refresh token carries this value, and a revoked family is
 * refused before its `activeJti` is compared.
 */
export const REVOKED_WITHOUT_RECORD_JTI = "revoked-without-record";

/**
 * RefreshTokenFamilyRevocation composition.
 *
 * `revokeFamily` is idempotent: aborting the updater on already-revoked
 * state classifies as "aborted" at the storage layer, which the wrapper
 * treats as success (the desired end-state is reached).
 *
 * A revocation lasts as long as its record, so the revoking write also sets
 * how long that is (`retention.mts`): until the later of the family's own
 * expiry and the moment the last access token it could have minted stops
 * being accepted. A family whose record has already run out — its refresh
 * tokens expired, an access token minted late in its life still live — is
 * recorded as revoked all the same, by registering a revoked record for it;
 * "not found" used to be a no-op, which left those access tokens passing the
 * family check with the revocation acknowledged.
 *
 * Note (#274): the refresh-grant replay path no longer routes through here —
 * `createRefreshTokenFamilyRotation` revokes inside the same compare-and-swap
 * that detects the replay, and keeps the record by the same rule. This
 * wrapper remains the entry point for revocations that are NOT a replay
 * classification: admin operations, logout cascade, and the caller's
 * fail-closed fallback for a custom rotation implementation that reports
 * `replayed` without `familyRevoked: true`.
 *
 * `isFamilyRevoked` is read-only via findFamily; returns false if the
 * family does not exist or the `revoked` flag is false.
 *
 * Per A3 §6.2.
 */
export function createRefreshTokenFamilyRevocation(
	deps: RefreshTokenFamilyRevocationDeps,
): RefreshTokenFamilyRevocation {
	const store = deps.refreshTokenFamilyStore;
	const horizonMs = assertAccessTokenHorizonMs(
		deps.accessTokenHorizonMs,
		"createRefreshTokenFamilyRevocation",
	);
	return {
		async revokeFamily(familyId) {
			const nowMs = Date.now();
			// Two passes at most: a record that appears between "not found" and
			// the registration below (a concurrent revocation writing the same
			// record) is revoked, or found revoked, by the second update.
			for (let attempt = 0; attempt < 2; attempt++) {
				const result = await store.updateFamily(familyId, (current) => {
					if (current.revoked) return { action: "abort" }; // already revoked, no-op
					// Freeze the committed family mirroring rotation.mts (defence-in-depth).
					// Adapters also freeze returned families, but freezing here is the
					// declared updater convention so future wrapper code that reads the
					// returned family does not encounter a mutable handle.
					return {
						action: "commit",
						family: Object.freeze({
							...current,
							revoked: true,
							expiresAtMs: revokedFamilyExpiresAtMs(current, nowMs, horizonMs),
						}),
					};
				});
				// committed: flipped revoked: false -> true, kept for the rule's
				// retention; aborted: already revoked.
				if (result.outcome !== "not-found") return;
				try {
					await store.registerFamily(
						Object.freeze({
							familyId,
							activeJti: REVOKED_WITHOUT_RECORD_JTI,
							revoked: true,
							expiresAtMs: revokedFamilyExpiresAtMs({ expiresAtMs: nowMs }, nowMs, horizonMs),
						}),
					);
					return;
				} catch (err) {
					if (err instanceof RefreshTokenStorageError && err.reason === "duplicate-family") {
						continue;
					}
					throw err;
				}
			}
			// The record kept appearing and vanishing under us: the revocation
			// is not known to be recorded, and a caller must not report it as
			// done.
			throw new RefreshTokenStorageError({ reason: "conflict-exhausted" });
		},

		async isFamilyRevoked(familyId) {
			const family = await store.findFamily(familyId);
			return family?.revoked ?? false;
		},
	};
}
