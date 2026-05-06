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

export interface RedisSidSortedSetOptions {
	readonly client: SessionSidSortedSetClient;
	readonly keyPrefix: string;
}

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
 * Process-restart behaviour: the counter resets to 0. If the same Redis key
 * survives a restart (i.e. it has not yet TTL-expired), new members added
 * after restart may receive a lower score than pre-restart members and
 * therefore sort ahead of them. In practice this case cannot occur because
 * PEXPIREAT synchronises key lifetime to session.expiresAt; a restarted
 * process issues a new session (new key prefix) before any add.
 *
 * JavaScript `number` range: 2^53 - 1 ≈ 9 × 10^15. At 1 million adds/second
 * the counter overflows after ~285 years — treated as unbounded in practice.
 */
let _insertionCounter = 0;

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
 */
export function createRedisSidSortedSet(opts: RedisSidSortedSetOptions): RedisSidSortedSet {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
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
