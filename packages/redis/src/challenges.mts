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
	isStorableExpiry,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { ChallengeStoreClient } from "./clients.mjs";

/**
 * Options for createRedisChallengeStore.
 */
export interface RedisChallengeStoreOptions {
	readonly client: ChallengeStoreClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed ChallengeStore. All three ops are 1-Redis-op atomic primitives:
 *   - issue:   SET <prefix><key> "1" PX <ttlMs> NX  → "OK" | null. `PX` takes
 *              whole milliseconds, so a fractional remaining life is rounded
 *              up; a non-finite expiry is refused before Redis is asked.
 *   - find:    PTTL <prefix><key>                   → -2 absent, -1 no-TTL, ≥0 ms
 *   - consume: DEL <prefix><key>                    → count deleted
 *
 * No Lua, no MULTI/EXEC: the contract is split into primitives so that no
 * transaction block is needed. If PTTL returns -1 (key without expiry, e.g.
 * external mutation), `find` returns null (fail-closed).
 */
export function createRedisChallengeStore(opts: RedisChallengeStoreOptions): ChallengeStore {
	const { client, keyPrefix } = opts;
	const fullKey = (scope: string, value: string): string =>
		`${keyPrefix}${canonicalChallengeKey(scope, value)}`;

	return {
		kind: "redis",

		async issue(scope, value, expiresAtMs) {
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`ChallengeStore.issue: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(fullKey(scope, value), "1", "PX", Math.ceil(ttlMs), "NX");
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
			return { expiresAtMs: Date.now() + pttl };
		},

		async consume(scope, value) {
			const count = await client.del(fullKey(scope, value));
			return count > 0;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection.
 * Consumer registers via:
 *   factory.register("redis", redisChallengeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "chal:" });
 */
export const redisChallengeStoreBuilder: AdapterBuilder<ChallengeStore> = (config, _ctx) => {
	const c = config as { client?: ChallengeStoreClient; keyPrefix?: string };
	// Structural guard: fail at boot rather than at the first Redis op with
	// a cryptic `Cannot read properties of undefined`.
	if (!c.client) {
		throw new Error("redisChallengeStoreBuilder: 'client' option is required");
	}
	return createRedisChallengeStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "chal:",
	});
};

/**
 * `defineModule` manifest for the Redis ChallengeStore. Static composition
 * path. For runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisChallengeStore` (module-namespaced — NO
 * bare `keyPrefix` top-level key).
 */
export const redisChallengeStoreModule = defineModule({
	name: "redis-challenge-store",
	requires: ["challengeStoreClient", "config"] as const,
	configSchema: z.object({
		redisChallengeStore: z
			.object({
				keyPrefix: z.string().default("chal:"),
			})
			.default({ keyPrefix: "chal:" }),
	}),
	provides: {
		challengeStore: (deps) => {
			const cfg = (deps.config as unknown as { redisChallengeStore: { keyPrefix: string } })
				.redisChallengeStore;
			return createRedisChallengeStore({
				client: deps.challengeStoreClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
