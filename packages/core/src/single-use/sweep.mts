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
 * Both stores are keyed by values that are never presented again once they
 * are done with — a finished or abandoned ceremony's challenge, an honoured
 * assertion's `jti` — so reclaiming an entry only when it is looked up again
 * reclaims almost nothing, and the sweep has to be its own step. It is
 * amortized on the store's writes rather than run on a timer: a background
 * interval would need lifecycle registration to avoid holding the process
 * open, and a write is the only operation that grows the map. The count
 * bounds the work per write; the floor bounds the O(size) scans per second
 * whatever the write rate. The floor is measured on the monotonic clock
 * (`performance.now()`), so a wall clock stepped back cannot stall sweeps;
 * which entries are expired stays the store's call, on the wall clock their
 * expiries are written in. Writes keep counting through the floor, so the
 * first write after it sweeps.
 *
 * The result is bounded growth, not zero-lag reclamation: the resident set is
 * the live entries plus at most those that expired within one interval.
 */

/** How a store's sweep is paced. A bad value falls back to the store's default rather than disabling the sweep. */
export interface AmortizedSweepOptions {
	/** Writes between sweeps. A non-integer or non-positive value falls back to the default. */
	readonly sweepInterval?: number;
	/**
	 * The least time between two sweeps, in milliseconds. `0` sweeps on the
	 * write interval alone. A negative or non-integer value falls back to the
	 * default rather than being read as no floor.
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

export function createAmortizedSweep(
	options: AmortizedSweepOptions,
	defaults: { readonly sweepInterval: number; readonly minSweepIntervalMs: number },
): AmortizedSweep {
	const sweepInterval =
		typeof options.sweepInterval === "number" &&
		Number.isInteger(options.sweepInterval) &&
		options.sweepInterval > 0
			? options.sweepInterval
			: defaults.sweepInterval;
	const minSweepIntervalMs =
		typeof options.minSweepIntervalMs === "number" &&
		Number.isInteger(options.minSweepIntervalMs) &&
		options.minSweepIntervalMs >= 0
			? options.minSweepIntervalMs
			: defaults.minSweepIntervalMs;
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
