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

/**
 * When the in-process challenge store and replay seen-set sweep their expired
 * entries: once `sweepInterval` writes have accumulated **and** at least
 * `minSweepIntervalMs` has passed since the last sweep.
 *
 * Their keys (a finished ceremony's challenge, an honoured assertion's `jti`)
 * are never looked up again, so reclaiming on lookup reclaims almost nothing.
 * The sweep rides on writes, the only operation that grows the map, rather
 * than a timer that would need lifecycle registration to not hold the
 * process open. The count bounds the work per write; the floor bounds the
 * O(size) scans per second, and runs on the monotonic clock so a wall clock
 * stepped back cannot stall sweeps (expiry itself stays on the wall clock).
 * The resident set is the live entries plus at most those that expired
 * within one interval.
 */

/**
 * How a store's sweep is paced; each value left out (`undefined`) takes the
 * store's default.
 * A value given that cannot be used is a `RangeError` naming the store and
 * the option — never replaced by the default, which would leave a setting
 * that says one thing and a store that does another.
 */
export interface AmortizedSweepOptions {
	/** Writes between sweeps: a positive whole number. */
	readonly sweepInterval?: number;
	/**
	 * The least time between two sweeps: a whole number of milliseconds, `0`
	 * or more. `0` sweeps on the write interval alone.
	 */
	readonly minSweepIntervalMs?: number;
}

export interface AmortizedSweep {
	/** Count one write; `true` when the caller is to sweep now. */
	wrote(): boolean;
	/**
	 * `true` when the caller may sweep now whatever the write count — at
	 * least `minSweepIntervalMs` since the last sweep — and counts it as that
	 * sweep. For a store at its cap, which reclaims what has expired before it
	 * refuses: a sweep per refused write would make each one O(size) under
	 * the flood that fills it.
	 */
	due(): boolean;
}

/**
 * The pacing for a store: `owner` names it (the factory the options were
 * given to) in the refusal of an option it cannot use.
 */
export function createAmortizedSweep(
	options: AmortizedSweepOptions,
	defaults: { readonly sweepInterval: number; readonly minSweepIntervalMs: number },
	owner: string,
): AmortizedSweep {
	// Only a setting left out takes the default: an explicit `null` is refused.
	const sweepInterval =
		options.sweepInterval === undefined ? defaults.sweepInterval : options.sweepInterval;
	if (!Number.isInteger(sweepInterval) || sweepInterval <= 0) {
		throw new RangeError(
			`${owner}: sweepInterval must be a positive whole number (got ${String(sweepInterval)})`,
		);
	}
	const minSweepIntervalMs =
		options.minSweepIntervalMs === undefined
			? defaults.minSweepIntervalMs
			: options.minSweepIntervalMs;
	if (!Number.isInteger(minSweepIntervalMs) || minSweepIntervalMs < 0) {
		throw new RangeError(
			`${owner}: minSweepIntervalMs must be a whole number of milliseconds, 0 or more (got ${String(minSweepIntervalMs)})`,
		);
	}
	let writesSinceSweep = 0;
	let lastSweepAtMonotonicMs = Number.NEGATIVE_INFINITY;

	/** Past the floor: record the sweep and answer `true`. */
	const pastFloor = (): boolean => {
		const monotonicMs = performance.now();
		if (monotonicMs - lastSweepAtMonotonicMs < minSweepIntervalMs) return false;
		writesSinceSweep = 0;
		lastSweepAtMonotonicMs = monotonicMs;
		return true;
	};

	return {
		wrote() {
			writesSinceSweep += 1;
			if (writesSinceSweep < sweepInterval) return false;
			return pastFloor();
		},
		due: pastFloor,
	};
}
