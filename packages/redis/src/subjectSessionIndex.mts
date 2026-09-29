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

import type { AdapterBuilder, SubjectSessionIndex } from "@o3co/auth-provider-core";
import type { SubjectSessionIndexClient } from "./clients.mjs";

/**
 * Redis {@link SubjectSessionIndex}: a subject's live sessions, which
 * `revokeAllForSubject` enumerates to cascade over (a password reset, for one)
 * on deployments using `redisSessionStoresModule`.
 *
 * One sorted set per subject, each member scored by its session's expiry in
 * epoch ms, so listing and GC are one command each on the server's clock. Not
 * the sid-keyed sorted-set client: that keeps one expiry per key, and a
 * subject's sessions do not share one.
 *
 * The key also carries a TTL, the latest member expiry and only ever raised
 * (`pExpireGT`), so a subject who never logs in again leaves the keyspace and a
 * shorter session added later cannot expire the whole set early. It is set in
 * the same `multi` as the write, so a write cannot land without its expiry.
 *
 * There is no background sweep: `listSids` prunes and reads in one server-side
 * operation (`pruneExpiredAndList`) on the store's clock. The calling replica's
 * clock would compare against a score another host wrote, and one operation
 * keeps the sweep and the read agreed on the boundary member. Redis deletes an
 * emptied sorted set itself.
 */
export interface RedisSubjectSessionIndexOptions {
	readonly client: SubjectSessionIndexClient;
	/** Defaults to the bundle's production layout, `ss:sub:`. */
	readonly keyPrefix?: string;
}

export function createRedisSubjectSessionIndex(
	deps: RedisSubjectSessionIndexOptions,
): SubjectSessionIndex {
	const prefix = deps.keyPrefix ?? "ss:sub:";
	const key = (subject: string): string => `${prefix}${subject}`;

	return {
		kind: "redis",

		async addSid(subject, sid, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// A NaN score and a NaN deadline are both Redis errors; a caller
			// fault, refused before Redis is asked.
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError("SubjectSessionIndex.addSid: expiresAt must be a valid date");
			}
			// An already-expired session is not worth indexing, as in the
			// in-process adapter. The local clock is fine here: `expiresAt` was
			// computed on this host, and this is only a short-circuit; the
			// server-clock sweep in `listSids` is the correctness gate.
			if (expiresAtMs <= Date.now()) return;
			const k = key(subject);
			await deps.client
				.multi()
				.zAdd(k, { score: expiresAtMs, value: sid })
				.pExpireGT(k, expiresAtMs)
				.exec();
		},

		async listSids(subject) {
			return deps.client.pruneExpiredAndList(key(subject));
		},

		async removeSid(subject, sid) {
			// Redis removes a sorted set that loses its last member, so there is no
			// emptied-key case to clean up here.
			await deps.client.zRem(key(subject), sid);
		},

		async removeBySubject(subject) {
			await deps.client.unlink(key(subject));
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SubjectSessionIndex`, for
 * per-adapter granularity; `redisSessionStoresModule` covers the common case.
 * The default `keyPrefix` (`ss:sub:`) matches that bundle's, so switching
 * between them keeps the keyspace. A missing `client` throws at boot.
 */
export const redisSubjectSessionIndexBuilder: AdapterBuilder<SubjectSessionIndex> = (
	config,
	_ctx,
) => {
	const c = config as { client?: SubjectSessionIndexClient; keyPrefix?: string };
	if (!c.client) {
		throw new Error("redisSubjectSessionIndexBuilder: 'client' option is required");
	}
	return createRedisSubjectSessionIndex({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:sub:",
	});
};
