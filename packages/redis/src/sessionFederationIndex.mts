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

import type { AdapterBuilder, SessionFederationIndex } from "@o3co/auth-provider-core";
import type { SessionSidSortedSetClient } from "./clients.mjs";
import { createRedisSidSortedSet } from "./internal/redisSidSortedSet.mjs";

export interface RedisSessionFederationIndexOptions {
	readonly client: SessionSidSortedSetClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed SessionFederationIndex over `createRedisSidSortedSet` (a ZSET
 * scored in insertion order, `ZADD NX`).
 *
 * `listFederations(sid)` MUST return names in insertion order, oldest first:
 * `routes/logout.mts` uses the first for the IdP post-logout redirect.
 * `ZADD NX` keeps a re-added member's original score, so it does not move.
 * `removeFederation` removes one element, which federation logout completion
 * needs, as distinct from the whole-session `removeBySid`.
 */
export function createRedisSessionFederationIndex(
	opts: RedisSessionFederationIndexOptions,
): SessionFederationIndex {
	const zset = createRedisSidSortedSet({ client: opts.client, keyPrefix: opts.keyPrefix });
	return {
		kind: "redis",
		async addFederation(sid, federationName, expiresAt) {
			await zset.add(sid, federationName, expiresAt);
		},
		async listFederations(sid) {
			return zset.list(sid);
		},
		async removeFederation(sid, federationName) {
			await zset.remove(sid, federationName);
		},
		async removeBySid(sid) {
			await zset.removeBySid(sid);
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SessionFederationIndex`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` is the bundle's (`ss:fed:`), so
 * switching between the two keeps the keyspace. A missing `client` throws at
 * boot, as in `redisChallengeStoreBuilder`, rather than at the first command.
 */
export const redisSessionFederationIndexBuilder: AdapterBuilder<SessionFederationIndex> = (
	config,
	_ctx,
) => {
	const c = config as { client?: SessionSidSortedSetClient; keyPrefix?: string };
	if (!c.client) {
		throw new Error("redisSessionFederationIndexBuilder: 'client' option is required");
	}
	return createRedisSessionFederationIndex({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:fed:",
	});
};
