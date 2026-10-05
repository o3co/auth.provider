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
import { assertAccessTokenHorizonMs, revokedFamilyExpiresAtMs } from "./retention.mjs";
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyRotation,
	RefreshTokenFamilyStore,
} from "./types.mjs";

/** Inputs for the RefreshTokenFamilyRotation composition. */
export interface RefreshTokenFamilyRotationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
	/**
	 * The longest an access token carrying a family's id can live, in
	 * milliseconds — `resolveFamilyAccessTokenHorizonMs(config)`. A replay
	 * revokes the family, and the revoked record is kept until the last
	 * access token it could have minted stops being accepted
	 * (`retention.mts`). Required for the reason the revocation wrapper's is.
	 */
	readonly accessTokenHorizonMs: number;
}

/**
 * Reasons this wrapper attaches to its `updateFamily` decisions. They come back
 * on the result (`RefreshTokenFamilyUpdateResult.reason`), so the outcome is
 * classified by the decision that settled the CAS. Internal to this
 * composition; the store treats them as opaque.
 */
const REASON_REPLAY_REVOKED = "replay-detected-family-revoked";
const REASON_ALREADY_REVOKED = "family-already-revoked";

/**
 * Builds a fresh `RefreshTokenFamily` on `register`, and maps
 * `RefreshTokenFamilyStore.updateFamily` outcomes to a
 * `RefreshTokenFamilyRotationOutcome` on `rotate`.
 *
 * A replay is revoked inside the CAS: the replay branch commits
 * `{ ...current, revoked: true }` (kept until the last access token the family
 * could have minted stops being accepted, `retention.mts`), so detection and
 * revocation are one write. RFC 6819 §5.2.2.3 wants the whole family dead on
 * replay; with two writes, a parallel request holding the active sibling token
 * could rotate in between and walk away with a fresh access token. The CAS
 * orders any sibling rotation strictly before the replay was classified or
 * strictly after the revocation.
 *
 * The commit is tagged `REASON_REPLAY_REVOKED` because a committed revocation
 * and an ordinary rotation both read `committed`, and the adapter may run the
 * updater more than once. An already-revoked family aborts: there is nothing to
 * write, and rewriting would amplify writes on a path an attacker can drive.
 * Any other abort classifies fail-closed as `replayed`.
 */
export function createRefreshTokenFamilyRotation(
	deps: RefreshTokenFamilyRotationDeps,
): RefreshTokenFamilyRotation {
	const horizonMs = assertAccessTokenHorizonMs(
		deps.accessTokenHorizonMs,
		"createRefreshTokenFamilyRotation",
	);
	return {
		async register(newJti, familyId, expiresAtMs) {
			const family: RefreshTokenFamily = Object.freeze({
				familyId,
				activeJti: newJti,
				revoked: false,
				expiresAtMs,
			});
			await deps.refreshTokenFamilyStore.registerFamily(family);
		},

		async rotate(previousJti, newJti, familyId, expiresAtMs) {
			const nowMs = Date.now();
			const result = await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
				if (current.revoked) {
					// Nothing to write — the end state this branch wants is
					// already durable.
					return { action: "abort", reason: REASON_ALREADY_REVOKED };
				}
				if (current.activeJti !== previousJti) {
					// The replay is the revocation, in one indivisible write.
					// `activeJti` stays: a revoked family keeps the jti that was
					// active when it died, and installing the replayed one would
					// record the attacker's token as the live one.
					return {
						action: "commit",
						family: Object.freeze({
							...current,
							revoked: true,
							expiresAtMs: revokedFamilyExpiresAtMs(current, nowMs, horizonMs),
						}),
						reason: REASON_REPLAY_REVOKED,
					};
				}
				// Absolute expiry cap (OAuth 2.1 BCP §4.14.1): the family TTL is set
				// once at creation and rotation never extends it; a smaller caller
				// value (e.g. a session-bound RT) is honoured. The outcome's
				// `cappedExpiresAtMs` reads the committed record; consumers read
				// the outcome's field.
				const cappedExpiresAtMs = Math.min(expiresAtMs, current.expiresAtMs);
				return {
					action: "commit",
					family: Object.freeze({
						...current,
						activeJti: newJti,
						expiresAtMs: cappedExpiresAtMs,
					}),
				};
			});

			switch (result.outcome) {
				case "not-found":
					return Object.freeze({ outcome: "unknown_family" } as const);
				case "aborted":
					// Only the already-revoked branch aborts. Anything else that
					// somehow aborts is classified fail-closed as a replay.
					return result.reason === REASON_ALREADY_REVOKED
						? Object.freeze({ outcome: "revoked" } as const)
						: Object.freeze({ outcome: "replayed", familyRevoked: false } as const);
				case "committed":
					if (result.reason === REASON_REPLAY_REVOKED) {
						// The family was revoked by this very commit, so the caller
						// MUST NOT revoke it again; `familyRevoked` says so explicitly.
						return Object.freeze({ outcome: "replayed", familyRevoked: true } as const);
					}
					// The committed ceiling, so the grant can issue the refresh
					// token at no more than it when the cap reduced the request.
					return Object.freeze({
						outcome: "rotated",
						cappedExpiresAtMs: result.family.expiresAtMs,
					} as const);
			}
		},
	};
}
