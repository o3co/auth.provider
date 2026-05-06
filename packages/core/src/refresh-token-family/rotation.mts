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
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyRotation,
	RefreshTokenFamilyRotationOutcome,
	RefreshTokenFamilyStore,
} from "./types.mjs";

/**
 * Inputs for the RefreshTokenFamilyRotation composition.
 * Per A3 §6.1.
 */
export interface RefreshTokenFamilyRotationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}

/**
 * RefreshTokenFamilyRotation composition: builds a fresh
 * RefreshTokenFamily aggregate on `register`, and translates
 * RefreshTokenFamilyStore.updateFamily outcomes into the 4-variant
 * RefreshTokenFamilyRotationOutcome on `rotate`.
 *
 * The closure-captured `abortReason` is reset at the top of every updater
 * invocation so CAS retries observe the freshest classification (the LAST
 * updater invocation determines the abort reason).
 *
 * Defence-in-depth fallback `?? "replayed"` on the aborted branch: if a
 * future code path adds an abort case that forgets to set `abortReason`,
 * the safest classification is "replayed" (caller rejects either way;
 * defaulting to a reject-class outcome is fail-closed).
 *
 * Per A3 §6.1.
 */
export function createRefreshTokenFamilyRotation(
	deps: RefreshTokenFamilyRotationDeps,
): RefreshTokenFamilyRotation {
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
			let abortReason: "replayed" | "revoked" | null = null;

			const result = await deps.refreshTokenFamilyStore.updateFamily(familyId, (current) => {
				abortReason = null; // reset on every updater invocation
				if (current.revoked) {
					abortReason = "revoked";
					return null;
				}
				if (current.activeJti !== previousJti) {
					abortReason = "replayed";
					return null;
				}
				// IH-13: absolute expiry cap. The family TTL is SET ONCE at
				// creation. Subsequent rotations MUST NOT extend the ceiling
				// — `Math.min` clamps a sliding-window-style request back to
				// the original creation value (or honours a smaller caller-
				// supplied value, e.g. a session-bound RT). Per OAuth 2.1
				// BCP §4.14.1.
				const cappedExpiresAtMs = Math.min(expiresAtMs, current.expiresAtMs);
				return Object.freeze({
					...current,
					activeJti: newJti,
					expiresAtMs: cappedExpiresAtMs,
				});
			});

			switch (result.outcome) {
				case "not-found":
					return Object.freeze({ outcome: "unknown_family" } as const);
				case "aborted":
					return Object.freeze({
						outcome: abortReason ?? "replayed",
					} as const) as RefreshTokenFamilyRotationOutcome;
				case "committed":
					// IH-13: surface the committed ceiling so the grant handler
					// can detect when the cap reduced the requested expiry and
					// (Phase F) re-mint the issued JWT to match. For v0.5.1
					// the storage cap alone is the security primary; JWT exp
					// alignment is deferred per the spec's open question.
					return Object.freeze({
						outcome: "rotated",
						cappedExpiresAtMs: result.family.expiresAtMs,
					} as const);
			}
		},
	};
}
