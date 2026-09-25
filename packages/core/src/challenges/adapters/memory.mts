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

import { isStorableExpiry } from "../../adapters/expiry.mjs";
import { canonicalKey } from "../../single-use/canonical-key.mjs";
import { ChallengeStorageError } from "../../single-use/errors.mjs";
import { usableMaxEntries } from "../../single-use/max-entries.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../../single-use/sweep.mjs";
import type { Challenge, ChallengeStore } from "../types.mjs";

/**
 * How many writing `issue` calls pass between amortized sweeps.
 *
 * A sweep is O(size), so one per issue would make every WebAuthn options
 * request linear in the store. Every 1000th write keeps the amortized cost
 * constant while bounding the resident set at "live challenges, plus at most
 * one interval of expired ones" — the replay seen-set's trade, for the same
 * kind of store.
 */
export const DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL = 1_000;

/**
 * The least time, in milliseconds, between two sweeps, whatever the issue
 * rate.
 *
 * The write interval alone does not bound how often the O(size) scan runs:
 * WebAuthn authentication options are asked for without a credential, so a
 * client that asks fast enough would reach the interval every few
 * milliseconds and make each request pay for a full scan. With a ten-second
 * floor the scans are at
 * most one per ten seconds, and the resident set grows by at most the
 * challenges that expire inside those ten seconds.
 */
export const DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS = 10_000;

/**
 * The most challenges the store holds by default.
 *
 * The store fills at `maxEntries / window` challenges a second, the window
 * being the ceremony's (`webauthn.challengeTtlMs`, 120 s by default): at a
 * million that is over 8 000 options requests a second held for two minutes,
 * more than one process serves, and the authentication options route is
 * behind a per-IP rate limit besides. The memory it bounds is about 180 MB.
 * A longer window lowers the rate that fills it in proportion.
 * `memoryChallengeStoreModule` reads the cap from
 * `challengeStore.memory.maxEntries`; past one replica, use the Redis
 * challenge store.
 */
export const DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES = 1_000_000;

/**
 * How the sweep is paced — `sweepInterval` writing `issue` calls, and at
 * least `minSweepIntervalMs` between two sweeps (see
 * {@link AmortizedSweepOptions}) — and the cap on the challenges it holds.
 */
export interface MemoryChallengeStoreOptions extends AmortizedSweepOptions {
	/**
	 * The most challenges the store holds, expired-but-unswept ones included;
	 * {@link DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES} when absent. A value
	 * that is not a positive whole number, or is above 2^24 (the most entries
	 * a `Map` holds), is a `RangeError`, never read as no cap.
	 */
	readonly maxEntries?: number;
}

/**
 * What `issue` throws when the store is at its cap and none of its
 * challenges has expired: a store fault, as a Redis store's refused write at
 * `maxmemory` is — not one of the port's own refusals (`ChallengeStorageError`
 * `duplicate` / `expired-at-issue`, a `RangeError`), which a caller reads as
 * something it did. The WebAuthn options routes answer it `503
 * temporarily_unavailable`. `reason` is `"full"`, which a logged projection
 * keeps.
 */
export class ChallengeStoreFullError extends Error {
	readonly reason = "full" as const;

	constructor(maxEntries: number) {
		super(
			`memory ChallengeStore is at its cap of ${maxEntries} live challenges; refusing a new one rather than evicting one`,
		);
		this.name = "ChallengeStoreFullError";
	}
}

/** In-process challenge store, with the entry count and its cap exposed for observability. */
export interface MemoryChallengeStore extends ChallengeStore {
	/** Challenges currently resident, expired-but-unswept included. */
	readonly size: number;
	/** The most challenges it holds (`maxEntries`); at it, a new challenge is refused. */
	readonly maxEntries: number;
}

/**
 * In-process Map-backed ChallengeStore. Atomicity comes from the Node.js
 * single-event-loop guarantee: synchronous Map.get → check → Map.set/Map.delete
 * blocks contain NO `await`, so concurrent calls cannot interleave at micro-
 * task boundaries.
 *
 * ## Why the sweep exists
 *
 * An expired challenge is dropped when its (scope, value) is looked up again,
 * and a challenge nobody finishes is never looked up again: a WebAuthn prompt
 * the user closes, an options request a client repeats. Lazy reclamation
 * alone therefore left one entry per abandoned ceremony resident until the
 * process restarted — and authentication options are asked for without a
 * credential, so anyone could grow the map.
 *
 * The sweep is the replay seen-set's, paced by the same schedule
 * (`single-use/sweep.mts`): amortized on the writing `issue`, once
 * `sweepInterval` writes have accumulated and at least `minSweepIntervalMs`
 * has passed on the monotonic clock since the last one. A refused `issue` — a
 * duplicate, an expiry already past or not a number — writes nothing and pays
 * nothing. The guarantee is bounded growth, not zero-lag reclamation: an
 * expired challenge is dropped within an interval, and `find` / `consume` /
 * `issue` keep answering correctly for one that has not been swept yet.
 *
 * ## Why it has a cap, and refuses at it
 *
 * The sweep bounds the store by time, not by count: what it holds is the
 * challenges issued within their window, so the issue rate — anyone's, for
 * authentication options — and the configured window decide its size.
 * `maxEntries` bounds it. At the cap the store first reclaims what has
 * expired, at most once per sweep floor, so a flood that holds it at the cap
 * does not make every issue a full scan; if it is still full it refuses the
 * new challenge with {@link ChallengeStoreFullError}, a store fault. It never
 * evicts a live challenge to make room: that would fail the ceremony of a
 * user already in front of their authenticator, and a consumed challenge
 * frees its slot at once. A duplicate is still answered as a duplicate.
 *
 * Per A1 §7.1.
 */
export function createMemoryChallengeStore(
	options: MemoryChallengeStoreOptions = {},
): MemoryChallengeStore {
	const maxEntries = usableMaxEntries(
		options.maxEntries ?? DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES,
		"createMemoryChallengeStore",
	);
	const map = new Map<string, { expiresAtMs: number }>();
	const schedule = createAmortizedSweep(
		options,
		{
			sweepInterval: DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL,
			minSweepIntervalMs: DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS,
		},
		"createMemoryChallengeStore",
	);

	function getLive(key: string, nowMs: number): { expiresAtMs: number } | undefined {
		const entry = map.get(key);
		if (entry === undefined) return undefined;
		if (entry.expiresAtMs <= nowMs) {
			map.delete(key);
			return undefined;
		}
		return entry;
	}

	function sweep(nowMs: number): void {
		for (const [key, entry] of map) {
			if (entry.expiresAtMs <= nowMs) map.delete(key);
		}
	}

	return {
		kind: "memory",

		get size() {
			return map.size;
		},

		maxEntries,

		async issue(scope, value, expiresAtMs) {
			// NaN is never `<= now`, and ±Infinity is no expiry: without this the
			// challenge would be kept forever (the sweep never drops it either).
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`ChallengeStore.issue: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const nowMs = Date.now();
			if (expiresAtMs <= nowMs) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const key = canonicalKey(scope, value);
			if (getLive(key, nowMs) !== undefined) {
				throw new ChallengeStorageError({ reason: "duplicate" });
			}
			// At the cap: reclaim what has expired, no more often than the sweep
			// floor, and refuse if the store is still full. See "Why it has a
			// cap, and refuses at it" above.
			if (map.size >= maxEntries) {
				if (schedule.due()) sweep(nowMs);
				if (map.size >= maxEntries) throw new ChallengeStoreFullError(maxEntries);
			}
			map.set(key, { expiresAtMs });
			if (schedule.wrote()) sweep(nowMs);
		},

		async find(scope, value): Promise<Challenge | null> {
			const entry = getLive(canonicalKey(scope, value), Date.now());
			if (entry === undefined) return null;
			return { expiresAtMs: entry.expiresAtMs };
		},

		async consume(scope, value) {
			const key = canonicalKey(scope, value);
			const entry = getLive(key, Date.now());
			if (entry === undefined) return false;
			map.delete(key);
			return true;
		},
	};
}
