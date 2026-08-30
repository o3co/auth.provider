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
 * ## Why the sweep exists (#293 item 6)
 *
 * GC used to be lazy on `has` alone: an entry was reclaimed only if someone
 * presented that exact jti again *after* it expired. For a **revoked** token
 * that is precisely the request that stops coming, so nothing was ever
 * reclaimed and every revocation became a permanent Map entry on a
 * long-running single-process deployment.
 *
 * The sibling in-memory stores are bounded by what they key on — the rate
 * limiter caps buckets and evicts, the subject stores are keyed by subject, so
 * both are bounded by population. This one is keyed by jti, where nothing
 * bounds it but time. The sweep therefore has to be its own step rather than a
 * side effect of a lucky read.
 *
 * Amortized on `add` rather than on a timer: a background interval would need
 * lifecycle registration to avoid holding the process open, and a store this
 * simple should not need a shutdown hook. `add` is also the only operation that
 * grows the map, which makes it the honest place to pay for the growth. The
 * guarantee is therefore bounded growth, not zero-lag reclamation — an expired
 * entry is dropped **within** an interval, and `has` keeps answering correctly
 * for one that has not been swept yet.
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
