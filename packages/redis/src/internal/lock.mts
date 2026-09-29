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

import { randomUUID } from "node:crypto";
import {
	type AcquireLockOptions,
	isStorableLifetime,
	type LockResult,
	type SupportsLock,
} from "@o3co/auth-provider-core";

/**
 * The Redis client shape the lock needs: node-redis, ioredis, or a fake in
 * tests. A client wired in MUST keep this contract:
 *
 * - `set(key, value, { NX: true, PX: ttlMs })` returns a truthy value (the
 *   stored string or `"OK"`) when it created the key, and `null` when the key
 *   already existed. Any non-null return counts as acquired.
 * - `PX` is in milliseconds, as in Redis, and always a positive integer:
 *   `acquireLock` refuses a `ttlMs` that is not a positive finite number and
 *   rounds a fractional one up.
 * - `compareAndDelete(key, expectedValue)` atomically deletes the key only
 *   when its value equals `expectedValue`, and never degrades to a GET+DEL
 *   pair: between the two, a holder whose TTL expired could evict a lock
 *   another process had since acquired.
 *
 * Breaking it fails silently: the release fails its value-match check and
 * never deletes, the TTL reclaims the key, and under load the lock starves.
 */
export interface RedisLockClient {
	set(key: string, value: string, opts?: { PX?: number; NX?: boolean }): Promise<string | null>;
	compareAndDelete(key: string, expectedValue: string): Promise<boolean>;
}

export interface RedisLockOptions {
	client: RedisLockClient;
	/** Default: "ftlock:" */
	keyPrefix?: string;
}

const DEFAULT_TTL_MS = 5_000;
const DEFAULT_WAIT_MS = 4_000;
const POLL_INTERVAL_MS = 50;

/**
 * Redis-backed advisory lock. `SET NX PX` acquires it; a compare-and-delete
 * releases it, checking the caller's token and deleting the key in one
 * server-side step, so no window lies between the check and the delete.
 *
 * `makeIoredisClients()` implements `compareAndDelete` with Lua `EVAL` (cached
 * through `EVALSHA`). A custom `FederationTokenStoreClient` MUST provide an
 * atomic one; a Cluster deployment with Lua scripting disabled needs another
 * atomic primitive. See `FederationTokenStoreClient.compareAndDelete`.
 */
export function createRedisLock(opts: RedisLockOptions): Pick<SupportsLock, "acquireLock"> {
	const prefix = opts.keyPrefix ?? "ftlock:";
	const k = (sid: string, name: string) => `${prefix}${sid}:${name}`;

	return {
		async acquireLock(a: AcquireLockOptions): Promise<LockResult> {
			const key = k(a.sid, a.federationName);
			const ttlMs = a.ttlMs ?? DEFAULT_TTL_MS;
			const waitForMs = a.waitForMs ?? DEFAULT_WAIT_MS;
			// The rule the federation-grant lock keeps: a TTL of NaN is `PX NaN`,
			// and an infinite one is not a lease; a wait of NaN is a deadline no
			// clock reaches, so a held lock would be polled for ever.
			if (!isStorableLifetime(ttlMs)) {
				throw new RangeError(
					`acquireLock: ttlMs must be a positive finite number that ends within the Date range (got ${String(ttlMs)})`,
				);
			}
			if (!isStorableLifetime(waitForMs, { allowZero: true })) {
				throw new RangeError(
					`acquireLock: waitForMs must be a non-negative finite number that ends within the Date range (got ${String(waitForMs)})`,
				);
			}
			// Rounded up: `PX` takes whole milliseconds, and a lease rounded down
			// would end before the holder was told it would.
			const px = Math.ceil(ttlMs);
			const deadline = Date.now() + waitForMs;
			const token = randomUUID();

			while (true) {
				const result = await opts.client.set(key, token, { PX: px, NX: true });
				if (result !== null) {
					return {
						acquired: true,
						release: async () => {
							// Deletes only while the key still holds our token, so a lock
							// acquired after our TTL expired is not evicted. `false` (we
							// no longer hold it) needs nothing done.
							await opts.client.compareAndDelete(key, token);
						},
					};
				}
				if (Date.now() >= deadline) {
					return { acquired: false, reason: "timeout" };
				}
				await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
			}
		},
	};
}
