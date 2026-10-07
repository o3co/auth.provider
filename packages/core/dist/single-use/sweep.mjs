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
 * The pacing for a store: `owner` names it (the factory the options were
 * given to) in the refusal of an option it cannot use.
 */
export function createAmortizedSweep(options, defaults, owner) {
    // Only a setting left out takes the default: an explicit `null` is refused.
    const sweepInterval = options.sweepInterval === undefined ? defaults.sweepInterval : options.sweepInterval;
    if (!Number.isInteger(sweepInterval) || sweepInterval <= 0) {
        throw new RangeError(`${owner}: sweepInterval must be a positive whole number (got ${String(sweepInterval)})`);
    }
    const minSweepIntervalMs = options.minSweepIntervalMs === undefined
        ? defaults.minSweepIntervalMs
        : options.minSweepIntervalMs;
    if (!Number.isInteger(minSweepIntervalMs) || minSweepIntervalMs < 0) {
        throw new RangeError(`${owner}: minSweepIntervalMs must be a whole number of milliseconds, 0 or more (got ${String(minSweepIntervalMs)})`);
    }
    let writesSinceSweep = 0;
    let lastSweepAtMonotonicMs = Number.NEGATIVE_INFINITY;
    /** Past the floor: record the sweep and answer `true`. */
    const pastFloor = () => {
        const monotonicMs = performance.now();
        if (monotonicMs - lastSweepAtMonotonicMs < minSweepIntervalMs)
            return false;
        writesSinceSweep = 0;
        lastSweepAtMonotonicMs = monotonicMs;
        return true;
    };
    return {
        wrote() {
            writesSinceSweep += 1;
            if (writesSinceSweep < sweepInterval)
                return false;
            return pastFloor();
        },
        due: pastFloor,
    };
}
