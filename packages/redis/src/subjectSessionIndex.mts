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
 * ## Read prunes
 *
 * There is no background sweep, so `listSids` is the only chance to reclaim.
 * It prunes and reads in one pipeline against a single `now`, so the two
 * commands cannot disagree about which members are live. An emptied sorted set
 * is removed by Redis itself, which is what keeps the keyspace from holding an
 * entry for everyone who ever logged in.
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
			if (expiresAtMs <= Date.now()) return;
			const k = key(subject);
			await deps.client
				.multi()
				.zAdd(k, { score: expiresAtMs, value: sid })
				.pExpireGT(k, expiresAtMs)
				.exec();
		},

		async listSids(subject) {
			// One `now` for both commands, so the sweep and the read cannot
			// disagree about the boundary member.
			//
			// Deliberately two round-trips rather than one pipeline. The pipeline's
			// `exec` hands back the driver's raw reply — ioredis returns one
			// `[error, result]` tuple per command — and reaching into that here
			// would put one driver's wire shape into an adapter the client
			// interface exists to keep vendor-agnostic. Nothing is lost by
			// splitting them: a concurrent `addSid` between the two carries a
			// future score and is included by the read, and a concurrent `removeSid`
			// is honoured. Only the write path is pipelined, where the pairing is
			// load-bearing (#269).
			const now = Date.now();
			const k = key(subject);
			await deps.client.zRemRangeByScore(k, "-inf", now);
			return deps.client.zRangeByScore(k, now, "+inf");
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
