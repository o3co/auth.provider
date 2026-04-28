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
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { z } from "zod";
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

/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisReplaySeenSetBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "replay:" });
 */
export const redisReplaySeenSetBuilder: AdapterBuilder<ReplaySeenSet> = (config) => {
	const c = config as { client: RedisClient; keyPrefix?: string };
	return createRedisReplaySeenSet({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "replay:",
	});
};

/**
 * `defineModule` manifest for the Redis ReplaySeenSet. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisReplaySeenSet` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export const redisReplaySeenSetModule = defineModule({
	name: "redis-replay-seen-set",
	requires: ["redisClient", "config"] as const,
	configSchema: z.object({
		redisReplaySeenSet: z
			.object({
				keyPrefix: z.string().default("replay:"),
			})
			.default({ keyPrefix: "replay:" }),
	}),
	provides: {
		replaySeenSet: (deps) => {
			const cfg = (deps.config as { redisReplaySeenSet: { keyPrefix: string } }).redisReplaySeenSet;
			return createRedisReplaySeenSet({
				client: deps.redisClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
