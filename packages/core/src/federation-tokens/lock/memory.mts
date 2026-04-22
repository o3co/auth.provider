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

import type { AcquireLockOptions, LockResult, SupportsLock } from "../types.mjs";

const lockKey = (sid: string, name: string) => `${sid}\u0000${name}`;
const DEFAULT_TTL_MS = 5_000;
const DEFAULT_WAIT_MS = 4_000;
const POLL_INTERVAL_MS = 50;

/**
 * Creates a single-process advisory lock usable by the in-memory
 * FederationTokenStore adapter. Not shared across processes — use
 * the redis lock (Task 3) for multi-process deployments.
 *
 * Stale entries (TTL-expired but never re-acquired) remain in the internal
 * Map until the next acquire of the same (sid, federationName) pair. For the
 * F-6 use case — one lock per active refresh cycle, TTL ≤ 5s — this is a
 * negligible bounded cost; deployments with very high distinct-session churn
 * and rare re-locks on the same federation can rely on process recycling
 * for final cleanup.
 */
export function createInProcessLock(): Pick<SupportsLock, "acquireLock"> {
	const holders = new Map<string, { expiresAt: number; token: symbol }>();

	const tryAcquire = (key: string, ttlMs: number): symbol | null => {
		const now = Date.now();
		const held = holders.get(key);
		if (held && held.expiresAt > now) return null;
		const token = Symbol("ft-lock");
		holders.set(key, { expiresAt: now + ttlMs, token });
		return token;
	};

	return {
		async acquireLock(opts: AcquireLockOptions): Promise<LockResult> {
			const key = lockKey(opts.sid, opts.federationName);
			const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
			const waitForMs = opts.waitForMs ?? DEFAULT_WAIT_MS;
			const deadline = Date.now() + waitForMs;

			while (true) {
				const token = tryAcquire(key, ttlMs);
				if (token !== null) {
					return {
						acquired: true,
						release: async () => {
							// Compare-and-delete: only remove the entry when we still own it.
							// Defends against release-after-TTL-expiry racing with another acquirer.
							const current = holders.get(key);
							if (current?.token === token) {
								holders.delete(key);
							}
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
