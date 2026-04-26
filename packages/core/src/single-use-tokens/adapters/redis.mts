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

import { canonicalKey } from "../keyEncoding.mjs";
import {
	type SingleUseConsumeOutcome,
	type SingleUseMarkSeenOutcome,
	SingleUseTokenError,
	type SingleUseTokenStoreBase,
} from "../types.mjs";

/**
 * Subset of the redis v5 client surface used by SingleUseTokenStore. Per
 * existing convention (federation-tokens, user-sessions), each store defines
 * its own `RedisLikeClient` shape so the dependency is local and testable
 * with a hand-rolled fake.
 *
 * Naming follows redis v5 (`hSetNX`, `hGet`, `pExpire`); ioredis users can
 * adapt with a thin wrapper.
 */
export interface RedisLikeClient {
	set(key: string, value: string, opts?: { PX?: number; NX?: boolean }): Promise<string | null>;
	hSetNX(key: string, field: string, value: string): Promise<number>;
	hGet(key: string, field: string): Promise<string | null>;
	pExpire(key: string, ms: number): Promise<number>;
	del(key: string): Promise<number>;
}

export interface RedisSingleUseTokenStoreOptions {
	client: RedisLikeClient;
	/** Default: "stk:" (single-use token). */
	keyPrefix?: string;
}

const DEFAULT_KEY_PREFIX = "stk:";

const FIELD_ISSUED = "issued";
const FIELD_CONSUMED = "consumed";

export function createRedisSingleUseTokenStore(
	opts: RedisSingleUseTokenStoreOptions,
): SingleUseTokenStoreBase {
	const { client, keyPrefix = DEFAULT_KEY_PREFIX } = opts;

	const fullKey = (scope: string, key: string): string => `${keyPrefix}${canonicalKey(scope, key)}`;

	return {
		kind: "redis",

		async issue(scope, key, expiresAt) {
			const nowMs = Date.now();
			const ttlMs = expiresAt.getTime() - nowMs;
			if (ttlMs <= 0) {
				throw new SingleUseTokenError({ reason: "expired-at-issue" });
			}
			const k = fullKey(scope, key);
			// Atomically set the `issued` field only when it is absent.
			// `HSETNX` returns 1 on first write, 0 if the field (or key) already exists.
			const created = await client.hSetNX(k, FIELD_ISSUED, "1");
			if (created !== 1) {
				throw new SingleUseTokenError({ reason: "duplicate" });
			}
			// Apply TTL on the hash key. PEXPIRE returns 0 only if the key
			// vanished between HSETNX and here (process kill / network partition).
			// Clean up the orphaned hash so the next `issue` doesn't see a stale
			// duplicate; surface the failure to the caller.
			const expireResult = await client.pExpire(k, ttlMs);
			if (expireResult !== 1) {
				await client.del(k);
				throw new Error("redis: failed to set TTL on issued single-use token");
			}
		},

		async consume(scope, key): Promise<SingleUseConsumeOutcome> {
			const k = fullKey(scope, key);
			// Non-mutating existence check first. Only issued entries are eligible
			// for consumption. Reading `issued` before writing anything keeps stray
			// consumes ZERO side-effect, so partial failures (crash / netsplit
			// between commands) cannot leave behind a TTL-less hash that poisons
			// future legitimate issue/consume for the same (scope, key).
			// See spec §5.2.2 "Poisoning attack mitigation".
			const issued = await client.hGet(k, FIELD_ISSUED);
			if (issued === null) {
				return { outcome: "unknown" };
			}
			// `HSETNX consumed <ts>` is the atomic "first wins" primitive for keys
			// that are known to have been issued: exactly one concurrent caller
			// writes (returns 1), the rest return 0.
			const won = await client.hSetNX(k, FIELD_CONSUMED, Date.now().toString());
			return won === 1 ? { outcome: "consumed" } : { outcome: "replayed" };
		},

		async markSeen(scope, key, expiresAt): Promise<SingleUseMarkSeenOutcome> {
			const nowMs = Date.now();
			const ttlMs = expiresAt.getTime() - nowMs;
			if (ttlMs <= 0) {
				throw new SingleUseTokenError({ reason: "expired-at-issue" });
			}
			const result = await client.set(fullKey(scope, key), "1", { NX: true, PX: ttlMs });
			return result === "OK" ? { outcome: "fresh" } : { outcome: "replayed" };
		},
	};
}
