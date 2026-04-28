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
	type Challenge,
	ChallengeStorageError,
	type ChallengeStore,
	canonicalChallengeKey,
	defineModule,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RedisClient } from "./types.mjs";

/**
 * Options for createRedisChallengeStore.
 */
export interface RedisChallengeStoreOptions {
	readonly client: RedisClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed ChallengeStore. All three ops are 1-Redis-op atomic primitives:
 *   - issue:   SET <prefix><key> "1" PX <ttlMs> NX  → "OK" | null
 *   - find:    PTTL <prefix><key>                   → -2 absent, -1 no-TTL, ≥0 ms
 *   - consume: DEL <prefix><key>                    → count deleted
 *
 * No Lua, no MULTI/EXEC — explicitly rejected by Theme A (the entire reason
 * A1 split into primitives is to NOT need transaction blocks).
 *
 * No-TTL defensive handling: if PTTL returns -1 (key exists without expiry,
 * e.g. external mutation), `find` returns null (fail-closed for lifecycle).
 *
 * Per A1 §7.2.
 */
export function createRedisChallengeStore(opts: RedisChallengeStoreOptions): ChallengeStore {
	const { client, keyPrefix } = opts;
	const fullKey = (scope: string, value: string): string =>
		`${keyPrefix}${canonicalChallengeKey(scope, value)}`;

	return {
		kind: "redis",

		async issue(scope, value, expiresAt) {
			const ttlMs = expiresAt.getTime() - Date.now();
			if (ttlMs <= 0) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(fullKey(scope, value), "1", "PX", ttlMs, "NX");
			if (result === null) {
				throw new ChallengeStorageError({ reason: "duplicate" });
			}
		},

		async find(scope, value): Promise<Challenge | null> {
			const pttl = await client.pttl(fullKey(scope, value));
			if (pttl <= 0) {
				// -2 absent, -1 no-TTL, 0 expired exactly now → all treated as null.
				return null;
			}
			return { expiresAt: new Date(Date.now() + pttl) };
		},

		async consume(scope, value) {
			const count = await client.del(fullKey(scope, value));
			return count > 0;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisChallengeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "chal:" });
 */
export const redisChallengeStoreBuilder: AdapterBuilder<ChallengeStore> = (config) => {
	const c = config as { client: RedisClient; keyPrefix?: string };
	return createRedisChallengeStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "chal:",
	});
};

/**
 * `defineModule` manifest for the Redis ChallengeStore. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisChallengeStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export const redisChallengeStoreModule = defineModule({
	name: "redis-challenge-store",
	requires: ["redisClient", "config"] as const,
	configSchema: z.object({
		redisChallengeStore: z
			.object({
				keyPrefix: z.string().default("chal:"),
			})
			.default({ keyPrefix: "chal:" }),
	}),
	provides: {
		challengeStore: (deps) => {
			const cfg = (deps.config as { redisChallengeStore: { keyPrefix: string } })
				.redisChallengeStore;
			return createRedisChallengeStore({
				client: deps.redisClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
