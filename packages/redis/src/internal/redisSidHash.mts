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
	/**
	 * Fields requested per `HSCAN` round-trip. A hint to Redis, not a hard
	 * limit on a page's size. Default 100.
	 */
	readonly scanCount?: number;
}

const DEFAULT_SCAN_COUNT = 100;

export interface RedisSidHash {
	setField(sid: string, id: string, jsonValue: string, expiresAt: Date): Promise<void>;
	listValues(sid: string): Promise<string[]>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * Private redis helper used by `SessionRPRegistry`. Single-key HSET +
 * (`PEXPIREAT … NX` + `PEXPIREAT … GT`) pipeline keyed by
 * `${keyPrefix}${sid}`. Per A4 §7.2.1.
 *
 * **HASH-keyed-by-element-id rationale**: SADD-of-JSON cannot dedup by
 * `clientId` when other RP fields change (different bytewise JSON for the
 * same logical clientId would create duplicate entries). HSET dedups on
 * field name = `clientId`, semantically correct for RP upsert.
 *
 * **TTL contract**: callers MUST pass `session.expiresAt`. The `pExpireGT`
 * method emits a `PEXPIREAT … NX` + `PEXPIREAT … GT` pair: NX sets the TTL
 * on first write (a bare GT silently no-ops on a key with no existing TTL —
 * Redis treats no-TTL as infinite TTL for the GT flag), GT prevents TTL
 * truncation on stale-`expiresAt` concurrent writes (D-10 / CR-3).
 * Requires Redis 7.0+; v0.5.1 pins the floor to Redis 7.2 LTS.
 * `UserSession.expiresAt` is post-create immutable per A4 §5.1, so the
 * legal value is fixed at session-create time.
 *
 * **Writes after expiry are no-op**: prevents zombie keys with no TTL.
 *
 * **Reads are cursor-based** (`HSCAN`, #291). `HVALS` returned every field in
 * one reply whose size was bounded by nothing but how many relying parties a
 * session had accumulated — a single blocking command on the connection every
 * other adapter in this package shares, issued on the logout path. The trade
 * is that `HSCAN` can hand back the same field on more than one cursor when
 * the hash rehashes mid-iteration, so the read de-duplicates by field name.
 *
 * The read is paged, **not truncated**: `listRPs` feeds back-channel logout,
 * and a cap would silently skip notifying the relying parties past it.
 *
 * **Removal is `UNLINK`**, not `DEL` — freeing a session's whole RP hash is
 * not worth blocking the shared connection during a logout.
 */
export function createRedisSidHash(opts: RedisSidHashOptions): RedisSidHash {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const scanCount = opts.scanCount ?? DEFAULT_SCAN_COUNT;
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
			// Keyed by field so a field returned on two cursors counts once;
			// the later observation wins because it is the fresher read.
			// Insertion order is preserved, which HSCAN does not define anyway.
			const byField = new Map<string, string>();
			for await (const [field, value] of opts.client.hScanIterator(k(sid), { COUNT: scanCount })) {
				byField.set(field, value);
			}
			return [...byField.values()];
		},
		async removeBySid(sid) {
			await opts.client.unlink(k(sid));
		},
	};
}
