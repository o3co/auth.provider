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

import type { SessionFamilyIndex } from "@o3co/auth-provider-core";
import type { SessionSidSortedSetClient } from "./clients.mjs";
import { createRedisSidSortedSet } from "./internal/redisSidSortedSet.mjs";

export interface RedisSessionFamilyIndexOptions {
	readonly client: SessionSidSortedSetClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed SessionFamilyIndex. Wraps `createRedisSidSortedSet` (ZSET
 * with insertion-time score, ZADD NX). Per A4 §5.3 + §7.2.
 *
 * Order is informational for cascade revoke (caller iterates
 * order-independently); the helper choice is made for consistency with
 * `SessionFederationIndex` rather than functional dependency.
 */
export function createRedisSessionFamilyIndex(
	opts: RedisSessionFamilyIndexOptions,
): SessionFamilyIndex {
	const zset = createRedisSidSortedSet({ client: opts.client, keyPrefix: opts.keyPrefix });
	return {
		kind: "redis",
		async addFamilyId(sid, familyId, expiresAt) {
			await zset.add(sid, familyId, expiresAt);
		},
		async listFamilyIds(sid) {
			return zset.list(sid);
		},
		async removeBySid(sid) {
			await zset.removeBySid(sid);
		},
	};
}
