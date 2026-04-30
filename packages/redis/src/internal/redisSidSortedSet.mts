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

import type { RedisClient } from "../types.mjs";

export interface RedisSidSortedSetOptions {
	readonly client: RedisClient;
	readonly keyPrefix: string;
}

export interface RedisSidSortedSet {
	add(sid: string, member: string, expiresAt: Date): Promise<void>;
	list(sid: string): Promise<string[]>;
	remove(sid: string, member: string): Promise<void>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Private redis helper used by `SessionFamilyIndex` + `SessionFederationIndex`.
 * Single-key ZADD NX + PEXPIREAT pipeline keyed by `${keyPrefix}${sid}`.
 *
 * Per A4 §7.2.2.
 *
 * **NX semantics**: ZADD ... NX does NOT update the existing member's score.
 * Original insertion-time score is preserved, so re-add of an existing
 * member does NOT promote its position. Load-bearing for
 * `SessionFederationIndex` ordering contract (A4 §5.4).
 *
 * **TTL contract** (identical to `createRedisSidHash`): callers MUST pass
 * `session.expiresAt`; same-sid writes use the SAME `expiresAt`; writes
 * after expiry no-op.
 */
export function createRedisSidSortedSet(opts: RedisSidSortedSetOptions): RedisSidSortedSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	return {
		async add(sid, member, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			if (expiresAtMs <= Date.now()) return;
			const pipeline = opts.client.multi();
			pipeline.zAdd(k(sid), { score: Date.now(), value: member }, { NX: true });
			pipeline.pExpireAt(k(sid), expiresAtMs);
			await pipeline.exec();
		},
		async list(sid) {
			return opts.client.zRange(k(sid), 0, -1);
		},
		async remove(sid, member) {
			await opts.client.zRem(k(sid), member);
		},
		async removeBySid(sid) {
			await opts.client.del(k(sid));
		},
	};
}
