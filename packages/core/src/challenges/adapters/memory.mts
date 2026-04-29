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
import { canonicalKey } from "../canonical-key.mjs";
import { ChallengeStorageError } from "../errors.mjs";
import type { Challenge, ChallengeStore } from "../types.mjs";

/**
 * In-process Map-backed ChallengeStore. Atomicity comes from the Node.js
 * single-event-loop guarantee: synchronous Map.get → check → Map.set/Map.delete
 * blocks contain NO `await`, so concurrent calls cannot interleave at micro-
 * task boundaries.
 *
 * GC is lazy (per-operation cleanup of expired entries). No background sweep.
 *
 * Per A1 §7.1.
 */
export function createMemoryChallengeStore(): ChallengeStore {
	const map = new Map<string, { expiresAtMs: number }>();

	function getLive(key: string, nowMs: number): { expiresAtMs: number } | undefined {
		const entry = map.get(key);
		if (entry === undefined) return undefined;
		if (entry.expiresAtMs <= nowMs) {
			map.delete(key);
			return undefined;
		}
		return entry;
	}

	return {
		kind: "memory",

		async issue(scope, value, expiresAtMs) {
			const nowMs = Date.now();
			if (expiresAtMs <= nowMs) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const key = canonicalKey(scope, value);
			if (getLive(key, nowMs) !== undefined) {
				throw new ChallengeStorageError({ reason: "duplicate" });
			}
			map.set(key, { expiresAtMs });
		},

		async find(scope, value): Promise<Challenge | null> {
			const entry = getLive(canonicalKey(scope, value), Date.now());
			if (entry === undefined) return null;
			return { expiresAtMs: entry.expiresAtMs };
		},

		async consume(scope, value) {
			const key = canonicalKey(scope, value);
			const entry = getLive(key, Date.now());
			if (entry === undefined) return false;
			map.delete(key);
			return true;
		},
	};
}
