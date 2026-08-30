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
 * Redis {@link SubjectSessionIndex} (#321) — the missing half of #296.
 *
 * `revokeAllForSubject` needs to enumerate a subject's live sessions to cascade
 * over them. #296 shipped only an in-process index, so a deployment on
 * `redisSessionStoresModule` got `unavailable: ["subjectSessionIndex", …]` and
 * a password reset revoked nothing — on exactly the deployments that need it.
 *
 * ## One sorted set per subject, scored by expiry
 *
 * Score is the member's expiry in epoch milliseconds, so "live sessions" is
 * `ZRANGEBYSCORE key now +inf` and the GC sweep is
 * `ZREMRANGEBYSCORE key -inf now` — one command each, evaluated against the
 * **server's** clock, which is the only clock every replica agrees on.
 *
 * This is why the adapter does not reuse the sid-keyed sorted-set client. That
 * one keeps a single expiry per key, correct where every member belongs to one
 * session and shares its expiry; a subject's sessions do not, so a key-level
 * TTL would either keep an expired session listed or drop a live one early.
 *
 * ## The key still carries a TTL
 *
 * Per-member scores decide what is *listed*; the key-level TTL is what stops a
 * subject who never logs in again from living in the keyspace forever. It is
 * set to the latest member expiry and only ever raised (`pExpireGT`), so a
 * short-lived session added after a long-lived one cannot pull the whole
 * subject's set in with it. Paired with the write in one pipeline, because a
 * mutation whose expiry silently failed is the shape #269 paid for.
 *
 * ## Read prunes, on the store's clock
 *
 * There is no background sweep, so `listSids` is the only chance to reclaim.
 * It sweeps and reads in one server-side operation whose boundary is the
 * **store's** clock — see `pruneExpiredAndList`. Using the calling replica's
 * `Date.now()` would compare a score written by whichever replica handled the
 * login against whichever replica handles the read: two host clocks, and the
 * skew between them drops live sessions early or keeps expired ones listed.
 * One operation also makes the sweep and the read agree about the boundary
 * member, which two commands could not. An emptied sorted set is removed by
 * Redis itself, which keeps the keyspace from holding an entry for everyone
 * who ever logged in.
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
			// An already-expired session is not worth indexing; it would only be
			// swept on the next read. Mirrors the in-process adapter.
			//
			// This one comparison is deliberately local: `expiresAt` was computed
			// on this host, so checking it against this host's clock is
			// self-consistent, and it is an optimisation rather than the
			// correctness gate — the server-clock sweep in `listSids` is. Reading
			// the store's clock here would buy a round-trip to make a
			// short-circuit slightly more accurate.
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
 * AdapterFactory builder for the Redis-backed `SubjectSessionIndex` (#321).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:sub:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Missing `client` throws at boot rather than crashing at the first Redis op,
 * matching every other builder in this package.
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
