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

import type { SessionSidSortedSetClient } from "../clients.mjs";
import { assertPositiveInteger } from "./validate.mjs";

export interface RedisSidSortedSetOptions {
	readonly client: SessionSidSortedSetClient;
	readonly keyPrefix: string;
	/**
	 * Members read per `ZRANGE` round-trip in `list`. Default 100. A positive
	 * integer, checked at construction: it is the loop step, and a value that
	 * does not advance the cursor hangs `list()`.
	 */
	readonly pageSize?: number;
}

const DEFAULT_PAGE_SIZE = 100;

export interface RedisSidSortedSet {
	add(sid: string, member: string, expiresAt: Date): Promise<void>;
	list(sid: string): Promise<string[]>;
	remove(sid: string, member: string): Promise<void>;
	removeBySid(sid: string): Promise<void>;
}

/**
 * The ZADD score: a process-wide counter, so adds within one millisecond
 * still get strictly increasing scores. Redis returns equal scores in an order
 * of its own, which would break `SessionFederationIndex`'s insertion-order
 * contract.
 *
 * It starts at `Date.now()` at module load, so members added after a restart
 * score above those added before it to the same key (a session that survives
 * the restart keeps gaining family ids in the auth-code grant), unless the
 * previous process made more adds than milliseconds passed between the two
 * starts. A backward clock step (NTP, VM migration) can invert that. Not
 * cluster-wide: two replicas can emit the same score for one key. At 1M adds
 * a second it takes about 285 years to pass 2^53.
 */
let _insertionCounter = Date.now();

/**
 * Private Redis helper for `SessionFamilyIndex` and `SessionFederationIndex`:
 * a ZSET at `${keyPrefix}${sid}`, scored by `_insertionCounter`. `ZADD … NX`
 * keeps an existing member's score, so re-adding a member does not move it;
 * `SessionFederationIndex`'s ordering contract depends on that.
 *
 * TTL, as in `createRedisSidHash`: callers MUST pass `session.expiresAt`, the
 * same one for every write under a sid, and a write after expiry does nothing.
 * `pExpireGT` sends `PEXPIREAT … NX` then `PEXPIREAT … GT`: NX sets the TTL on
 * the first write (a bare GT does nothing on a key without a TTL), and GT
 * keeps a writer with a stale `expiresAt` from shortening a longer TTL. See
 * README, Requirements (Redis 7.0+).
 *
 * `list` pages by rank and never truncates: one `ZRANGE key 0 -1` reply would
 * grow with the session's families or federations and block the shared
 * connection on the logout path, and a cap would leave the families past it
 * live after a cascade revocation. Paging keeps the order, because `ZADD NX` with a rising
 * score only appends: a member added mid-read lands after the ranks already
 * walked. A concurrent `remove` shifts later ranks down by one and can drop a
 * member from that read; both callers (cascade revoke, the IdP-logout
 * redirect) re-read on the next request and treat no one listing as
 * authoritative. Removal is `UNLINK`, not `DEL`.
 */
export function createRedisSidSortedSet(opts: RedisSidSortedSetOptions): RedisSidSortedSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
	assertPositiveInteger(pageSize, "createRedisSidSortedSet: pageSize");
	return {
		async add(sid, member, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// `PEXPIREAT NaN` fails inside the MULTI after `ZADD` has run, leaving
			// the key with no TTL. Refused before Redis is asked.
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError("expiresAt must be a valid date");
			}
			if (expiresAtMs <= Date.now()) return;
			const score = ++_insertionCounter;
			const pipeline = opts.client.multi();
			pipeline.zAdd(k(sid), { score, value: member }, { NX: true });
			pipeline.pExpireGT(k(sid), expiresAtMs);
			await pipeline.exec();
		},
		async list(sid) {
			const all: string[] = [];
			for (let start = 0; ; start += pageSize) {
				const page = await opts.client.zRange(k(sid), start, start + pageSize - 1);
				all.push(...page);
				// A short page is the end of the set. A full one is not: an exact
				// multiple of `pageSize` needs one more round-trip to learn that.
				if (page.length < pageSize) return all;
			}
		},
		async remove(sid, member) {
			await opts.client.zRem(k(sid), member);
		},
		async removeBySid(sid) {
			await opts.client.unlink(k(sid));
		},
	};
}
