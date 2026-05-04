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
import type { ReplaySeenSet } from "../replay-seen-set/types.mjs";
import { ChallengeStorageError } from "./errors.mjs";
import type { ChallengeCeremony, ChallengeCeremonyOutcome, ChallengeStore } from "./types.mjs";

/**
 * Inputs for the 3-outcome challenge ceremony composition.
 * Per A1 §6 (lines 341-398).
 */
export interface ChallengeCeremonyDeps {
	readonly challengeStore: ChallengeStore;
	readonly replaySeenSet: ReplaySeenSet;
}

/**
 * ChallengeCeremony composition: combines ChallengeStore (issue/find/
 * consume) and ReplaySeenSet (markSeen/contains) into the 3-outcome wrapper
 * (consumed | replayed | unknown).
 *
 * Three-branch control flow:
 *   1. find → null     → contains → outcome `replayed | unknown`
 *   2. find → Challenge, consume → true  → markSeen (swallow expired-at-issue) → outcome `consumed`
 *   3. find → Challenge, consume → false → outcome `replayed` (race-loss / TTL boundary, fail-closed)
 *
 * Acknowledged consume→markSeen propagation gap (§6.1): sub-millisecond on
 * single Redis instance, ~1ms under realistic jitter. Bounded fraction of
 * sane challenge TTL. Security impact zero (both `unknown` and `replayed`
 * cause caller to reject). Audit signal impact bounded.
 *
 * Per A1 §6 + §6.1.
 */
export function createChallengeCeremony(deps: ChallengeCeremonyDeps): ChallengeCeremony {
	return {
		async consume(scope, value): Promise<ChallengeCeremonyOutcome> {
			// Step 1: find — lookup the challenge.
			const challenge = await deps.challengeStore.find(scope, value);

			if (challenge === null) {
				// Branch A: never-issued or already consumed + GC'd.
				// Probe replay set (read-only — zero storage amplification on probes).
				const seen = await deps.replaySeenSet.contains(scope, value);
				return Object.freeze({ outcome: seen ? "replayed" : "unknown" } as const);
			}

			// Step 2: consume — atomically delete.
			const won = await deps.challengeStore.consume(scope, value);

			if (won) {
				// Branch B: this call won the atomic delete. Record for replay detection.
				// Swallow markSeen "expired-at-issue" — TTL elapsed in sub-ms window
				// between find and markSeen; replay window already closed by the
				// atomic delete. Other errors (system / network) propagate.
				try {
					await deps.replaySeenSet.markSeen(scope, value, challenge.expiresAtMs);
				} catch (e) {
					if (!(e instanceof ChallengeStorageError && e.reason === "expired-at-issue")) {
						throw e;
					}
					// Suppress — TTL just elapsed, no replay window remains.
				}
				return Object.freeze({ outcome: "consumed" } as const);
			}

			// Branch C: consume returned false. Concurrent caller deleted between
			// find and consume (genuine race-loss) OR TTL elapsed in sub-ms window
			// (TTL boundary). Conservative classification: "replayed" (both cause
			// rejection; fail-closed for audit signalling).
			return Object.freeze({ outcome: "replayed" } as const);
		},
	};
}
