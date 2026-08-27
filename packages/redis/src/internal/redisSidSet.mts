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

/**
 * The slice of `FederationTokenStoreClient` this helper consumes. Named after
 * its consumer, like `SessionRPRegistryClient` and `SessionSidSortedSetClient`
 * are for the other two sid-keyed helpers.
 */
export type RedisSidSetClient = Pick<
	FederationTokenStoreClient,
	"sAddWithTtl" | "sRem" | "sScanIterator" | "unlink"
>;

export interface RedisSidSetOptions {
	readonly client: RedisSidSetClient;
	readonly keyPrefix: string;
	/**
	 * Members requested per `SSCAN` round-trip. A hint to Redis, not a hard
	 * limit on a page's size. Default 100 — the batch size the federation
	 * token store already used for its delete batches.
	 *
	 * Must be a positive integer — Redis refuses a non-positive `COUNT`.
	 * Validated at construction rather than discovered mid-logout.
	 */
	readonly scanCount?: number;
}

export interface RedisSidSet {
	add(sid: string, member: string, ttlMs: number): Promise<void>;
	remove(sid: string, member: string): Promise<void>;
	/** Cursor-based iteration over the sid's members. May yield duplicates. */
	members(sid: string): AsyncIterable<string>;
	removeBySid(sid: string): Promise<void>;
}

const DEFAULT_SCAN_COUNT = 100;

/**
 * Private redis helper: a sid-keyed SET at `${keyPrefix}${sid}`, third in the
 * family alongside `createRedisSidHash` (HASH) and `createRedisSidSortedSet`
 * (ZSET). Same key layout, same TTL contract, different Redis type — a SET is
 * what an unordered membership index of "which names exist under this sid"
 * actually is.
 *
 * Introduced for #291. The federation token store used to answer
 * "which federations does this sid have?" with `SCAN MATCH ft:<sid>:*`, which
 * is O(keys in the database) and runs on an end-user logout. This index
 * answers it in O(the session's federations).
 *
 * **TTL contract**: unlike its two siblings the caller passes a *relative*
 * `ttlMs`, not `session.expiresAt` — the federation token store's records live
 * on a fixed store TTL (an upper bound that must outlive the upstream
 * refresh_token), not on the session's expiry. `sAddWithTtl` applies the same
 * `PEXPIRE … NX` + `PEXPIRE … GT` pair the siblings use, so the index key
 * always outlives the envelopes it points at and no write can truncate a
 * further deadline. Atomicity of the add and its expiry is part of the client
 * contract rather than this helper's discipline: a persistent index key
 * outlives the session it describes.
 *
 * **Reads are paginated** (`SSCAN`), so a session linked to an unbounded
 * number of providers is walked in pages instead of materialised by one
 * `SMEMBERS`. `SSCAN` may return a member more than once; callers here only
 * ever delete, which is idempotent.
 *
 * **Removal is `UNLINK`**, not `DEL`: freeing the key is not worth blocking
 * the shared connection during a logout.
 */
export function createRedisSidSet(opts: RedisSidSetOptions): RedisSidSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const scanCount = opts.scanCount ?? DEFAULT_SCAN_COUNT;
	assertPositiveInteger(scanCount, "createRedisSidSet: scanCount");
	return {
		async add(sid, member, ttlMs) {
			await opts.client.sAddWithTtl(k(sid), member, ttlMs);
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
