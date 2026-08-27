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
	 * Members read per `ZRANGE` round-trip in `list`. Default 100.
	 *
	 * Must be a positive integer — this is the loop step, so a value that does
	 * not advance the cursor hangs `list()`. Validated at construction.
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
 * Module-level monotonic counter used as the ZADD score.
 *
 * Using `Date.now()` alone is insufficient for insertion-order guarantees:
 * multiple sequential `await add(...)` calls within the same millisecond
 * receive the same score, and Redis returns members with equal scores in an
 * undefined (lexicographic or internal hash) order — violating the
 * load-bearing ordering contract of `SessionFederationIndex` (A4 §5.4).
 *
 * A module-level auto-increment counter guarantees strict monotonicity across
 * all add() calls in the current process:
 *   - ZADD NX assigns the score on first add; subsequent adds for the same
 *     member are no-ops (score preserved), satisfying the NX contract.
 *   - ZRANGE ascending score == call-site insertion order unconditionally.
 *
 * Process-restart behaviour (OR-8): the counter is initialised from
 * `Date.now()` at module load. Epoch-ms in 2026 (~1.75×10^12) exceeds any
 * pre-crash counter that started at 0 and incremented once per `add()`,
 * provided the process did not run continuously at ~100k adds/sec for ~200
 * days — sufficient under realistic operational throughput, not
 * mathematically absolute. Post-restart members therefore receive scores
 * strictly greater than pre-crash members in the same Redis key, preserving
 * insertion order across restart boundaries for long-lived sessions (e.g.
 * 24 h TTL). Verified live path: `SessionFamilyIndex.addFamilyId` is called
 * after restart on a surviving session during the auth-code grant
 * (`packages/oauth/src/grants/authorization.mts`).
 *
 * Edge case: a backward system-clock step (NTP correction, VM migration)
 * can invert the guarantee. Phase F may switch to `process.hrtime.bigint()`.
 *
 * Non-goal: cluster-wide total ordering. Two replicas starting in the same
 * millisecond can independently emit identical scores against the same
 * Redis key — only single-process restart baseline inversion is fixed.
 * Cross-replica monotonic scores remain Phase F (e.g. Redis `INCR`).
 *
 * JavaScript `number` range: 2^53 - 1 ≈ 9 × 10^15. At 1M adds/second from
 * the Date.now() baseline (~1.75×10^12), headroom is ~7.25×10^15 — still
 * ~285 years before overflow. Treated as unbounded in practice.
 */
let _insertionCounter = Date.now();

/**
 * Private redis helper used by `SessionFamilyIndex` + `SessionFederationIndex`.
 * Single-key ZADD NX + (`PEXPIREAT … NX` + `PEXPIREAT … GT`) pipeline keyed
 * by `${keyPrefix}${sid}`.
 *
 * Per A4 §7.2.2.
 *
 * **NX semantics on ZADD**: ZADD ... NX does NOT update the existing member's
 * score. Original insertion-time score is preserved, so re-add of an existing
 * member does NOT promote its position. Load-bearing for
 * `SessionFederationIndex` ordering contract (A4 §5.4).
 *
 * **TTL contract** (identical to `createRedisSidHash`): callers MUST pass
 * `session.expiresAt`; same-sid writes use the SAME `expiresAt`; writes
 * after expiry no-op. The `pExpireGT` method emits a `PEXPIREAT … NX` +
 * `PEXPIREAT … GT` pair: NX sets the TTL on first write (a bare GT silently
 * no-ops on a key with no existing TTL), GT prevents TTL truncation when
 * a stale-`expiresAt` writer races against a longer existing TTL
 * (D-10 / CR-3). Requires Redis 7.0+; v0.5.1 pins the floor to Redis 7.2 LTS.
 *
 * **Score**: monotonic module-level counter (see `_insertionCounter` above).
 * The counter replaces `Date.now()` as the score source to guarantee strict
 * insertion-order even when multiple adds execute within the same millisecond.
 *
 * **`list` pages by rank** (#291). `ZRANGE key 0 -1` returned the whole set in
 * one reply whose size grew with how many families or federations a session
 * had accumulated, on the connection every other adapter shares and on the
 * logout path. Paging is safe for the ordering contract because ZADD NX with a
 * monotonically increasing score only ever appends: a member added mid-read
 * lands after the ranks already walked. A concurrent `remove` shifts later
 * ranks down by one and can drop a member from that read — acceptable here,
 * where the two callers (cascade revoke, IdP-logout redirect) both re-read on
 * the next request and neither treats one listing as authoritative.
 *
 * The read is paged, **not truncated**: `listFamilyIds` drives cascade
 * revocation, and a cap would silently leave the families past it live.
 *
 * **Removal is `UNLINK`**, not `DEL`.
 */
export function createRedisSidSortedSet(opts: RedisSidSortedSetOptions): RedisSidSortedSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
	assertPositiveInteger(pageSize, "createRedisSidSortedSet: pageSize");
	return {
		async add(sid, member, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// Guard: no-op writes after expiry.
			if (expiresAtMs <= Date.now()) return;
			// Monotonically increasing score — guarantees insertion order even
			// when multiple adds execute within the same millisecond.
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
