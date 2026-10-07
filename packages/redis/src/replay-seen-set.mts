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
	type AdapterBuilder,
	ChallengeStorageError,
	canonicalChallengeKey,
	defineModule,
	isStorableExpiry,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import type { ReplaySeenSetClient } from "./clients.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/**
 * Options for createRedisReplaySeenSet.
 */
export interface RedisReplaySeenSetOptions {
	readonly client: ReplaySeenSetClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed ReplaySeenSet, one Redis command per operation:
 *
 * - `markSeen`: `SET <prefix><key> "1" PX <ttlMs> NX`; `true` on `"OK"` (first
 *   observation), `false` on `null` (a replay). Unlike `ChallengeStore.issue`,
 *   which throws on a duplicate, it returns a boolean: a replay is an expected
 *   outcome here, not an error. `PX` takes whole milliseconds, so a fractional
 *   remaining life is rounded up (the record outlives its expiry by under a
 *   millisecond rather than dying before it); an expiry outside the Date range
 *   is refused before Redis is asked.
 * - `contains`: `EXISTS <prefix><key>`. A key without a TTL counts as present,
 *   failing closed for replay detection, where `ChallengeStore.find` answers
 *   `null` for one. The asymmetry keeps false "consumed" outcomes down; such
 *   keys surface as a conservative "replayed".
 */
export function createRedisReplaySeenSet(opts: RedisReplaySeenSetOptions): ReplaySeenSet {
	const { client, keyPrefix } = opts;
	const fullKey = (scope: string, key: string): string =>
		`${keyPrefix}${canonicalChallengeKey(scope, key)}`;

	return {
		kind: "redis",

		async markSeen(scope, key, expiresAtMs) {
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`ReplaySeenSet.markSeen: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(fullKey(scope, key), "1", "PX", Math.ceil(ttlMs), "NX");
			return result === "OK";
		},

		async contains(scope, key) {
			const result = await client.exists(fullKey(scope, key));
			return result === 1;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection:
 *   factory.register("redis", redisReplaySeenSetBuilder);
 *   factory.create({ type: "redis", client, keyPrefix: "replay:" });
 */
export const redisReplaySeenSetBuilder: AdapterBuilder<ReplaySeenSet> = (config, _ctx) => {
	const c = config as { client?: ReplaySeenSetClient; keyPrefix?: string };
	// Fails at boot on a missing client, as `redisFederationTokenStoreBuilder`
	// does, rather than with a cryptic crash at runtime.
	if (!c.client) {
		throw new Error("redisReplaySeenSetBuilder: 'client' option is required");
	}
	return createRedisReplaySeenSet({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "replay:",
	});
};

/**
 * `defineModule` manifest for the Redis ReplaySeenSet, for static
 * composition; for runtime-config-driven selection use the builder above.
 * Its section, `redis-replay-seen-set`, holds `keyPrefix` (strict).
 */
export const redisReplaySeenSetModule = defineModule({
	name: "redis-replay-seen-set",
	requires: ["replaySeenSetClient"] as const,
	section: {
		schema: keyPrefixSection,
		reference: redisReference(),
		relocatedFrom: { redisReplaySeenSet: { to: "", environmentVariable: null } },
	},
	provides: {
		replaySeenSet: ({ section, replaySeenSetClient }) =>
			createRedisReplaySeenSet({
				client: replaySeenSetClient,
				keyPrefix: section.keyPrefix,
			}),
	},
});
