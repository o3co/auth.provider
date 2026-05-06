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
import type { AcquireLockOptions, LockResult, SupportsLock } from "@o3co/auth-provider-core";

/**
 * Minimal redis client shape the lock needs. Consumers can pass any client
 * that implements these methods — node-redis, ioredis, fake clients in
 * tests, etc.
 *
 * ## Value-fidelity contract
 *
 * The compare-and-delete release path depends on two properties the lock
 * assumes of the client; consumers wiring a non-standard client MUST preserve
 * them:
 *
 * - `set(key, value, { NX: true, PX: ttlMs })` MUST return a truthy value (the
 *   stored string or `"OK"`) when the key was created, and MUST return `null`
 *   when creation was skipped because the key already exists. The lock treats
 *   any non-null return as acquire-success.
 *
 * - `PX` is in **milliseconds** (matching the redis native option).
 *
 * - `compareAndDelete(key, expectedValue)` MUST atomically delete the key only
 *   when its stored value equals `expectedValue`. Implementations MUST NOT
 *   degrade to a non-atomic GET+DEL pair under any condition — the race
 *   window the spec closes (CR-1, OR-13, SF-4) reopens if so.
 *
 * Breaking these invariants causes silent incorrectness: the release path
 * will fail its value-match check and never DEL, waiting for the TTL to
 * reclaim the key. Under load this manifests as lock starvation.
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
 * Redis-backed advisory lock. Uses SET NX PX for acquire and an atomic
 * compare-and-delete for release — the release path runs a Lua script (or
 * adapter-equivalent atomic operation) that compares the stored value to the
 * caller's acquire token and only deletes the key when they match in a single
 * server-side step.
 *
 * **Atomicity (D-9 / OR-13 / SF-4)**: there is no race window between checking
 * and deleting the key. Pre-D-9 the release was GET+DEL — a TTL-expired holder
 * could evict a freshly-acquired lock owned by a different process between
 * the two round-trips. The atomic `compareAndDelete` closes that race.
 *
 * Adapter responsibility: built-in `makeIoredisClients()` implements
 * `compareAndDelete` via Lua `EVAL` (with `EVALSHA` caching). Custom
 * `FederationTokenStoreClient` implementations MUST provide an atomic
 * implementation; degrading to GET+DEL reopens the race. Cluster-mode
 * deployments with Lua scripting disabled need an alternative atomic primitive.
 *
 * See `FederationTokenStoreClient.compareAndDelete` JSDoc for the contract.
 */
export function createRedisLock(opts: RedisLockOptions): Pick<SupportsLock, "acquireLock"> {
	const prefix = opts.keyPrefix ?? "ftlock:";
	const k = (sid: string, name: string) => `${prefix}${sid}:${name}`;

	return {
		async acquireLock(a: AcquireLockOptions): Promise<LockResult> {
			const key = k(a.sid, a.federationName);
			const ttlMs = a.ttlMs ?? DEFAULT_TTL_MS;
			const waitForMs = a.waitForMs ?? DEFAULT_WAIT_MS;
			const deadline = Date.now() + waitForMs;
			const token = randomUUID();

			while (true) {
				const result = await opts.client.set(key, token, { PX: ttlMs, NX: true });
				if (result !== null) {
					return {
						acquired: true,
						release: async () => {
							// Atomic compare-and-delete: deletes the key only when the
							// stored value equals our acquire token. Prevents evicting a
							// subsequently acquired lock after our TTL expired under a
							// slow operation. Return value is intentionally not checked —
							// `false` (caller no longer holds the lock) is a no-op outcome.
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
