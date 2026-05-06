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

import type { SessionRPRegistryClient } from "../clients.mjs";

export interface RedisSidHashOptions {
	readonly client: SessionRPRegistryClient;
	readonly keyPrefix: string;
}

export interface RedisSidHash {
	setField(sid: string, id: string, jsonValue: string, expiresAt: Date): Promise<void>;
	listValues(sid: string): Promise<string[]>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Private redis helper used by `SessionRPRegistry`. Single-key HSET +
 * PEXPIREAT … GT pipeline keyed by `${keyPrefix}${sid}`. Per A4 §7.2.1.
 *
 * **HASH-keyed-by-element-id rationale**: SADD-of-JSON cannot dedup by
 * `clientId` when other RP fields change (different bytewise JSON for the
 * same logical clientId would create duplicate entries). HSET dedups on
 * field name = `clientId`, semantically correct for RP upsert.
 *
 * **TTL contract**: callers MUST pass `session.expiresAt`. The `pExpireGT`
 * (PEXPIREAT … GT) modifier guards against stale-`expiresAt` writes
 * shortening the key's TTL on concurrent same-sid writes; D-10 / CR-3.
 * Requires Redis 7.0+; v0.5.1 pins the floor to Redis 7.2 LTS.
 * `UserSession.expiresAt` is post-create immutable per A4 §5.1, so the
 * legal value is fixed at session-create time.
 *
 * **Writes after expiry are no-op**: prevents zombie keys with no TTL.
 */
export function createRedisSidHash(opts: RedisSidHashOptions): RedisSidHash {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	return {
		async setField(sid, id, jsonValue, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			if (expiresAtMs <= Date.now()) return;
			const pipeline = opts.client.multi();
			pipeline.hSet(k(sid), id, jsonValue);
			pipeline.pExpireGT(k(sid), expiresAtMs);
			await pipeline.exec();
		},
		async listValues(sid) {
			return opts.client.hVals(k(sid));
		},
		async removeBySid(sid) {
			await opts.client.del(k(sid));
		},
	};
}
