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
import { assertPositiveInteger } from "./validate.mjs";

export interface RedisSidHashOptions {
	readonly client: SessionRPRegistryClient;
	readonly keyPrefix: string;
	/**
	 * Fields requested per `HSCAN` round-trip. A hint to Redis, not a hard
	 * limit on a page's size. Default 100. A positive integer, checked at
	 * construction: Redis refuses a non-positive `COUNT`.
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
 * Private Redis helper for `SessionRPRegistry`: a HASH at `${keyPrefix}${sid}`
 * with one field per relying party. A HASH rather than a SET of JSON, so an
 * upsert dedups on the field name (`clientId`) when the RP's other fields
 * change.
 *
 * TTL: callers MUST pass `session.expiresAt`, which is fixed when the session
 * is created. `pExpireGT` sends `PEXPIREAT … NX` then `PEXPIREAT … GT`: NX sets
 * the TTL on the first write (a bare GT does nothing on a key without a TTL,
 * which Redis treats as infinite), and GT keeps a concurrent write with a
 * stale `expiresAt` from shortening it. See README, Requirements (Redis 7.0+).
 * A write after expiry does nothing, so no key is left without a TTL.
 *
 * Reads are paged (`HSCAN`) and never truncated: one `HVALS` reply would be
 * bounded only by how many RPs the session accumulated and would block the
 * connection every adapter here shares, on the logout path, while a cap would
 * skip notifying the RPs past it in back-channel logout. `HSCAN` can return a
 * field on more than one cursor when the hash rehashes, so the read
 * de-duplicates by field name. Removal is `UNLINK`, so freeing the hash does
 * not block the shared connection during a logout.
 */
export function createRedisSidHash(opts: RedisSidHashOptions): RedisSidHash {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const scanCount = opts.scanCount ?? DEFAULT_SCAN_COUNT;
	assertPositiveInteger(scanCount, "createRedisSidHash: scanCount");
	return {
		async setField(sid, id, jsonValue, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// `PEXPIREAT NaN` fails inside the MULTI after `HSET` has run, leaving
			// the key with no TTL. Refused before Redis is asked.
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError("expiresAt must be a valid date");
			}
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
