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

import type {
	AdapterBuilder,
	SessionFamilyIndex,
	SupportsSessionEnd,
} from "@o3co/auth-provider-core";
import type { SessionFamilyIndexClient } from "./clients.mjs";
import { createRedisSidSortedSet } from "./internal/redisSidSortedSet.mjs";

export interface RedisSessionFamilyIndexOptions {
	readonly client: SessionFamilyIndexClient;
	readonly keyPrefix: string;
	/**
	 * Where the session's "ended" mark is kept: `${endedKeyPrefix}${sid}`. A
	 * namespace apart from `keyPrefix`'s, so no sid's family set shares a key
	 * with a mark. Without it the index has no `SupportsSessionEnd`.
	 */
	readonly endedKeyPrefix?: string;
}

/**
 * Redis-backed SessionFamilyIndex over `createRedisSidSortedSet` (a ZSET
 * scored in insertion order, `ZADD NX`). Cascade revoke does not depend on
 * the order; the sorted set is for consistency with `SessionFederationIndex`.
 *
 * Given `endedKeyPrefix` and a client with `writeEndMark` and `hasEndMark`, it
 * has core's `SupportsSessionEnd`. The mark is a string at
 * `${endedKeyPrefix}${sid}` expiring at the session's `expiresAt` (`PXAT`),
 * which `removeBySid` leaves. `endSession` writes the mark, then lists;
 * `addFamilyIdUnlessEnded` adds, then reads the mark: each command's reply is
 * in before the next is sent, so on a linearizable server one of the two sees
 * the other. The two keys need not share a Cluster slot.
 */
export function createRedisSessionFamilyIndex(
	opts: RedisSessionFamilyIndexOptions,
): SessionFamilyIndex {
	const zset = createRedisSidSortedSet({ client: opts.client, keyPrefix: opts.keyPrefix });
	const index: SessionFamilyIndex = {
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

	const { client, endedKeyPrefix } = opts;
	const writeEndMark = client.writeEndMark?.bind(client);
	const hasEndMark = client.hasEndMark?.bind(client);
	if (
		endedKeyPrefix === undefined ||
		typeof writeEndMark !== "function" ||
		typeof hasEndMark !== "function"
	) {
		return index;
	}
	const markKey = (sid: string): string => `${endedKeyPrefix}${sid}`;
	const sessionEnd: SupportsSessionEnd = {
		async endSession(sid, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// Refused before Redis is asked, as an add's is.
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError("expiresAt must be a valid date");
			}
			if (expiresAtMs > Date.now()) await writeEndMark(markKey(sid), expiresAtMs);
			return zset.list(sid);
		},
		async addFamilyIdUnlessEnded(sid, familyId, expiresAt) {
			if (!(await zset.add(sid, familyId, expiresAt))) return "ended";
			return (await hasEndMark(markKey(sid))) ? "ended" : "added";
		},
	};
	return { ...index, ...sessionEnd };
}

/**
 * AdapterFactory builder for the Redis-backed `SessionFamilyIndex`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` and `endedKeyPrefix` are the bundle's
 * (`ss:fi:`, `ss:fi-ended:`), so switching between the two keeps the
 * keyspace. A missing `client` throws at boot, as in
 * `redisChallengeStoreBuilder`, rather than at the first command.
 */
export const redisSessionFamilyIndexBuilder: AdapterBuilder<SessionFamilyIndex> = (
	config,
	_ctx,
) => {
	const c = config as {
		client?: SessionFamilyIndexClient;
		keyPrefix?: string;
		endedKeyPrefix?: string;
	};
	if (!c.client) {
		throw new Error("redisSessionFamilyIndexBuilder: 'client' option is required");
	}
	return createRedisSessionFamilyIndex({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:fi:",
		endedKeyPrefix: c.endedKeyPrefix ?? "ss:fi-ended:",
	});
};
