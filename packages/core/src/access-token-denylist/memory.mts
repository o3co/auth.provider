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

import { isStorableExpiry } from "../adapters/expiry.mjs";
import type { AccessTokenDenylist } from "./types.mjs";

/**
 * How many `add` calls pass between amortized sweeps.
 *
 * A sweep is O(size), so doing one per `add` would make revocation linear in
 * the denylist — the wrong trade on the path that revokes. Every 1000th add
 * keeps the amortized cost per revocation constant while bounding the resident
 * set at "live entries, plus at most one interval of expired ones".
 */
export const DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL = 1_000;

export interface MemoryAccessTokenDenylistOptions {
	/**
	 * `add` calls between sweeps. Lower trades work for memory; the default
	 * (1000) is sized so a sweep is invisible next to the token issuance a
	 * revocation implies. A non-integer or non-positive value falls back to the
	 * default rather than disabling the sweep.
	 */
	readonly sweepInterval?: number;
}

/** In-process denylist, with the entry count exposed for observability. */
export interface MemoryAccessTokenDenylist extends AccessTokenDenylist {
	/** Entries currently resident, expired-but-unswept included. */
	readonly size: number;
}

/**
 * In-process Map-backed AccessTokenDenylist.
 *
 * Keyed by jti, so nothing bounds it but time, and a revoked token is exactly
 * the one nobody presents again: reclaiming only on `has` would keep every
 * revocation forever. Expired entries are therefore swept, amortized on `add`
 * (the only operation that grows the map) rather than on a timer, which would
 * need lifecycle registration to avoid holding the process open. The guarantee
 * is bounded growth: an expired entry is dropped within one interval, and `has`
 * answers correctly for one not yet swept.
 *
 * Idempotent `add`: a second call for the same jti overwrites the expiry.
 */
export function createMemoryAccessTokenDenylist(
	options: MemoryAccessTokenDenylistOptions = {},
): MemoryAccessTokenDenylist {
	const entries = new Map<string, number>();
	const sweepInterval =
		typeof options.sweepInterval === "number" &&
		Number.isInteger(options.sweepInterval) &&
		options.sweepInterval > 0
			? options.sweepInterval
			: DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL;
	let addsSinceSweep = 0;

	const sweep = (now: number): void => {
		for (const [jti, expiresAtMs] of entries) {
			if (expiresAtMs <= now) entries.delete(jti);
		}
	};

	return {
		kind: "memory",

		get size() {
			return entries.size;
		},

		async add(jti, expiresAtMs) {
			// NaN is never `<= now`: the jti would stay denied forever and the
			// sweep would never drop it. ±Infinity is no expiry either.
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`AccessTokenDenylist.add: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			entries.set(jti, expiresAtMs);
			addsSinceSweep += 1;
			if (addsSinceSweep >= sweepInterval) {
				addsSinceSweep = 0;
				sweep(Date.now());
			}
		},

		async has(jti) {
			const expiresAtMs = entries.get(jti);
			if (expiresAtMs === undefined) return false;
			if (expiresAtMs <= Date.now()) {
				// Kept alongside the sweep: an expired entry must read as
				// not-revoked the moment it expires, not at the next sweep.
				entries.delete(jti);
				return false;
			}
			return true;
		},
	};
}
