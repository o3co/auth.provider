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

import type { FederationTokenStoreClient } from "../clients.mjs";
import { assertPositiveInteger } from "./validate.mjs";

/** The slice of `FederationTokenStoreClient` this helper consumes. */
export type RedisSidSetClient = Pick<
	FederationTokenStoreClient,
	"sAddWithTtl" | "sRem" | "sScanIterator" | "unlink" | "pExpireGT"
>;

export interface RedisSidSetOptions {
	readonly client: RedisSidSetClient;
	readonly keyPrefix: string;
	/**
	 * Members requested per `SSCAN` round-trip. A hint to Redis, not a hard
	 * limit on a page's size. Default 100. A positive integer, checked at
	 * construction: Redis refuses a non-positive `COUNT`.
	 */
	readonly scanCount?: number;
}

export interface RedisSidSet {
	add(sid: string, member: string, ttlMs: number): Promise<void>;
	/** Raises the sid's TTL to `ttlMs` from now when nearer: never lowers it, adds a member, or makes the key. */
	extend(sid: string, ttlMs: number): Promise<void>;
	remove(sid: string, member: string): Promise<void>;
	/** Cursor-based iteration over the sid's members. May yield duplicates. */
	members(sid: string): AsyncIterable<string>;
	removeBySid(sid: string): Promise<void>;
}

const DEFAULT_SCAN_COUNT = 100;

/**
 * Private Redis helper: an unordered sid-keyed SET at `${keyPrefix}${sid}`.
 * It lets the federation token store answer "which federations does this sid
 * have?" in O(the session's federations) rather than by a keyspace `SCAN` on
 * logout (README, Federation-token keys and logout).
 *
 * TTL: the caller passes a relative `ttlMs`, not `session.expiresAt`, because
 * the federation token store's records live on a fixed store TTL that must
 * outlive the upstream refresh token. `sAddWithTtl` applies a
 * `PEXPIRE … NX` + `PEXPIRE … GT` pair, so the index key
 * always outlives the envelopes it points at and no write can truncate a
 * further deadline. The add and its expiry being atomic is the client's
 * contract: a persistent index key would outlive the session it describes.
 *
 * Reads are paged (`SSCAN`) rather than one `SMEMBERS`. `SSCAN` may return a
 * member more than once; callers only delete, which is idempotent. Removal is
 * `UNLINK`, so freeing the key does not block the shared connection during a
 * logout.
 */
export function createRedisSidSet(opts: RedisSidSetOptions): RedisSidSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const scanCount = opts.scanCount ?? DEFAULT_SCAN_COUNT;
	assertPositiveInteger(scanCount, "createRedisSidSet: scanCount");
	return {
		async add(sid, member, ttlMs) {
			await opts.client.sAddWithTtl(k(sid), member, ttlMs);
		},
		async extend(sid, ttlMs) {
			await opts.client.pExpireGT(k(sid), ttlMs);
		},
		async remove(sid, member) {
			await opts.client.sRem(k(sid), member);
		},
		members(sid) {
			return opts.client.sScanIterator(k(sid), { COUNT: scanCount });
		},
		async removeBySid(sid) {
			await opts.client.unlink(k(sid));
		},
	};
}
