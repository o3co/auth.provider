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
	DEFAULT_CLOCK_SKEW_MS,
	type SessionFamilyIndex,
	type SupportsSessionEnd,
} from "@o3co/auth-provider-core";
import type { SessionFamilyIndexClient } from "./clients.mjs";
import { createRedisSidSortedSet } from "./internal/redisSidSortedSet.mjs";

export interface RedisSessionFamilyIndexOptions {
	readonly client: SessionFamilyIndexClient;
	readonly keyPrefix: string;
	/**
	 * Where the session's "ended" mark is kept: `${endedKeyPrefix}${sid}`. A
	 * namespace apart from `keyPrefix`'s — neither may start with the other, a
	 * `RangeError` at construction — so no sid's family set shares a key with a
	 * mark. Without it the index has no `SupportsSessionEnd`.
	 */
	readonly endedKeyPrefix?: string;
}

/**
 * Redis-backed SessionFamilyIndex over `createRedisSidSortedSet` (a ZSET
 * scored in insertion order, `ZADD NX`). Cascade revoke does not depend on
 * the order; the sorted set is for consistency with `SessionFederationIndex`.
 *
 * Given `endedKeyPrefix` and a client with `writeEndedMark` and `hasEndedMark`, it
 * has core's `SupportsSessionEnd`. The mark is a string at
 * `${endedKeyPrefix}${sid}` expiring at the session's `expiresAt` plus the
 * clock-skew allowance (`PXAT`), which `removeBySid` leaves. `endSession`
 * writes the mark, then lists; `addFamilyIdUnlessEnded` adds, then reads the
 * mark, then its clock: each command's reply is in before the next is sent,
 * so on a linearizable server one of the two sees the other. The two keys
 * need not share a Cluster slot.
 */
export function createRedisSessionFamilyIndex(
	opts: RedisSessionFamilyIndexOptions,
): SessionFamilyIndex {
	const { client, keyPrefix, endedKeyPrefix } = opts;
	if (
		endedKeyPrefix !== undefined &&
		(endedKeyPrefix.startsWith(keyPrefix) || keyPrefix.startsWith(endedKeyPrefix))
	) {
		throw new RangeError(
			`createRedisSessionFamilyIndex: endedKeyPrefix "${endedKeyPrefix}" and keyPrefix "${keyPrefix}" overlap; neither may start with the other`,
		);
	}
	const zset = createRedisSidSortedSet({ client, keyPrefix });
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

	const writeEndedMark = client.writeEndedMark?.bind(client);
	const hasEndedMark = client.hasEndedMark?.bind(client);
	if (
		endedKeyPrefix === undefined ||
		typeof writeEndedMark !== "function" ||
		typeof hasEndedMark !== "function"
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
			const until = expiresAtMs + DEFAULT_CLOCK_SKEW_MS;
			if (until > Date.now()) await writeEndedMark(markKey(sid), until);
			return zset.list(sid);
		},
		async addFamilyIdUnlessEnded(sid, familyId, expiresAt) {
			if (!(await zset.add(sid, familyId, expiresAt))) return "ended";
			if (await hasEndedMark(markKey(sid))) return "ended";
			// An absent mark read after `expiresAt` says nothing: it may have lapsed.
			return expiresAt.getTime() > Date.now() ? "added" : "ended";
		},
	};
	return { ...index, ...sessionEnd };
}

/**
 * AdapterFactory builder for the Redis-backed `SessionFamilyIndex`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` is the bundle's (`ss:fi:`), so
 * switching between the two keeps the keyspace, and so is the default
 * `endedKeyPrefix` (`ss:fi-ended:`), but only beside the default `keyPrefix`:
 * a `keyPrefix` of its own without an `endedKeyPrefix` builds an index
 * without the capability, rather than one whose marks share the bundle's
 * namespace. A missing `client` throws at boot, as in
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
		endedKeyPrefix: c.endedKeyPrefix ?? (c.keyPrefix === undefined ? "ss:fi-ended:" : undefined),
	});
};
