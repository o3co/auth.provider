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
import {
	ChallengeStorageError,
	canonicalChallengeKey,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import type { RedisClient } from "./types.mjs";

/**
 * Options for createRedisReplaySeenSet.
 */
export interface RedisReplaySeenSetOptions {
	readonly client: RedisClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed ReplaySeenSet. Two ops are 1-Redis-op primitives:
 *   - markSeen: SET <prefix><key> "1" PX <ttlMs> NX → "OK" | null
 *   - contains: EXISTS <prefix><key> → 1 | 0
 *
 * Note: markSeen returns true on "OK" (= first observation), false on null
 * (= already present, replay). This is the ONE difference from
 * ChallengeStore.issue which throws on duplicate — markSeen returns the
 * boolean because replays are an EXPECTED outcome of the wrapper, not an
 * error.
 *
 * No-TTL key defensive handling: contains treats a no-TTL key as present
 * (fail-closed for replay detection — asymmetric with ChallengeStore.find
 * which treats no-TTL as null for lifecycle fail-closed). The asymmetry
 * minimises false-positive "consumed" outcomes; sweeps surface as
 * conservative "replayed".
 *
 * Per A1 §7.2.
 */
export function createRedisReplaySeenSet(opts: RedisReplaySeenSetOptions): ReplaySeenSet {
	const { client, keyPrefix } = opts;
	const fullKey = (scope: string, key: string): string =>
		`${keyPrefix}${canonicalChallengeKey(scope, key)}`;

	return {
		kind: "redis",

		async markSeen(scope, key, expiresAt) {
			const ttlMs = expiresAt.getTime() - Date.now();
			if (ttlMs <= 0) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(fullKey(scope, key), "1", "PX", ttlMs, "NX");
			return result === "OK";
		},

		async contains(scope, key) {
			const result = await client.exists(fullKey(scope, key));
			return result === 1;
		},
	};
}
