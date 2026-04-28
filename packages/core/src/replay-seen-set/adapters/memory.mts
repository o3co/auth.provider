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
import { canonicalKey } from "../../challenges/canonical-key.mjs";
import { ChallengeStorageError } from "../../challenges/errors.mjs";
import type { ReplaySeenSet } from "../types.mjs";

/**
 * In-process Map-backed ReplaySeenSet. Same atomicity argument as the
 * memory ChallengeStore (Task 3): Node.js single-event-loop + no awaits
 * inside the critical section between Map.get/check and Map.set/delete.
 *
 * GC is lazy (per-operation cleanup of expired entries). No background sweep.
 *
 * The duplicated `getLive` helper (mirroring memory ChallengeStore) is
 * deliberate — Task 3 reviewer S2 confirmed three similar lines is preferable
 * to a premature abstraction; the two stores have semantically distinct
 * contracts (issue throws on duplicate; markSeen returns false on duplicate).
 *
 * Per A1 §7.1.
 */
export function createMemoryReplaySeenSet(): ReplaySeenSet {
	const map = new Map<string, { expiresAt: number }>();

	function getLive(key: string, nowMs: number): { expiresAt: number } | undefined {
		const entry = map.get(key);
		if (entry === undefined) return undefined;
		if (entry.expiresAt <= nowMs) {
			map.delete(key);
			return undefined;
		}
		return entry;
	}

	return {
		kind: "memory",

		async markSeen(scope, key, expiresAt) {
			const nowMs = Date.now();
			if (expiresAt.getTime() <= nowMs) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const k = canonicalKey(scope, key);
			if (getLive(k, nowMs) !== undefined) {
				return false;
			}
			map.set(k, { expiresAt: expiresAt.getTime() });
			return true;
		},

		async contains(scope, key) {
			return getLive(canonicalKey(scope, key), Date.now()) !== undefined;
		},
	};
}
