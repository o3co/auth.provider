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
	RefreshTokenFamilyStore,
	RefreshTokenRotation,
	RefreshTokenRotationOutcome,
} from "./types.mjs";

/**
 * Inputs for the default RefreshTokenRotation composition.
 * Per A3 §6.1.
 */
export interface DefaultRefreshTokenRotationDeps {
	readonly refreshTokenFamilyStore: RefreshTokenFamilyStore;
}

/**
 * Default RefreshTokenRotation composition: builds a fresh
 * RefreshTokenFamily aggregate on `register`, and translates
 * RefreshTokenFamilyStore.updateFamily outcomes into the 4-variant
 * RefreshTokenRotationOutcome on `rotate`.
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
export function createDefaultRefreshTokenRotation(
	deps: DefaultRefreshTokenRotationDeps,
): RefreshTokenRotation {
	return {
		async register(newJti, familyId, expiresAt) {
			const family: RefreshTokenFamily = Object.freeze({
				familyId,
				activeJti: newJti,
				revoked: false,
				expiresAt,
			});
			await deps.refreshTokenFamilyStore.registerFamily(family);
		},

		async rotate(previousJti, newJti, familyId, expiresAt) {
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
				return Object.freeze({
					...current,
					activeJti: newJti,
					expiresAt,
				});
			});

			switch (result.outcome) {
				case "not-found":
					return Object.freeze({ outcome: "unknown_family" } as const);
				case "aborted":
					return Object.freeze({
						outcome: abortReason ?? "replayed",
					} as const) as RefreshTokenRotationOutcome;
				case "committed":
					return Object.freeze({ outcome: "rotated" } as const);
			}
		},
	};
}
