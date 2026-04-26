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
 */
export interface RedisLikeClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, opts?: { PX?: number; NX?: boolean }): Promise<string | null>;
	pTTL(key: string): Promise<number>;
	eval(
		script: string,
		opts: { keys: string[]; arguments?: string[] },
	): Promise<string | number | null>;
}

export interface RedisSingleUseTokenStoreOptions {
	client: RedisLikeClient;
	/** Default: "stk:" (single-use token). */
	keyPrefix?: string;
}

const DEFAULT_KEY_PREFIX = "stk:";

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
			const result = await client.set(fullKey(scope, key), "issued", { NX: true, PX: ttlMs });
			if (result === null) {
				throw new SingleUseTokenError({ reason: "duplicate" });
			}
		},

		async consume(_scope, _key): Promise<SingleUseConsumeOutcome> {
			throw new Error("consume not implemented yet");
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
