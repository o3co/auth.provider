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

import type { SessionFederationIndex } from "@o3co/auth-provider-core";
import type { SessionSidSortedSetClient } from "./clients.mjs";
import { createRedisSidSortedSet } from "./internal/redisSidSortedSet.mjs";

export interface RedisSessionFederationIndexOptions {
	readonly client: SessionSidSortedSetClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed SessionFederationIndex. Wraps `createRedisSidSortedSet` (ZSET
 * with insertion-time score, ZADD NX). Per A4 §5.4 + §7.2.
 *
 * Ordering contract (load-bearing): `listFederations(sid)` returns federation
 * names in INSERTION order (oldest first). `routes/logout.mts` uses the first
 * element for IdP post-logout redirect. ZADD NX preserves original
 * insertion-time score so re-add of an existing member does NOT promote its
 * position.
 *
 * `removeFederation(sid, name)` delegates to `RedisSidSortedSet.remove` for
 * per-element removal (required for federation logout completion, distinct from
 * full-session `removeBySid`).
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
