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
 * The in-process `AttemptCounter`: one process's windows, lost on a restart,
 * so a limit it enforces is per replica. It holds at most `maxEntries` keys.
 * Full, it drops the windows that have ended and, if still full, evicts the
 * live window that ends first, warning `attempt_counter_evicted` (counts
 * only) at most once a minute. Evicting rather than refusing keeps a flood of
 * fresh keys from locking out every new client; an evicted key only starts
 * a new window, which gains nothing for a key its holder can mint anew.
 */

import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { usableMaxEntries } from "../single-use/max-entries.mjs";
import {
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	isAttemptKey,
	isAttemptSpec,
} from "./attempts.mjs";

export const DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES = 100_000;

/** The least time between two `attempt_counter_evicted` warnings. */
export const ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS = 60_000;

export interface MemoryAttemptCounterOptions {
	/** The most keys it holds a window for. Default {@link DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES}. */
	readonly maxEntries?: number;
	/** Epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
	/** Where an eviction is reported. Default `consoleLogger`. */
	readonly logger?: Pick<Logger, "warn">;
}

interface Window {
	count: number;
	readonly resetAt: number;
}

export function createMemoryAttemptCounter(
	options: MemoryAttemptCounterOptions = {},
): AttemptCounter {
	const maxEntries = usableMaxEntries(
		options.maxEntries ?? DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES,
		"createMemoryAttemptCounter",
	);
	const now = options.now ?? Date.now;
	const logger = options.logger ?? consoleLogger;
	const windows = new Map<string, Window>();
	let unreported = 0;
	let lastWarnAt = Number.NEGATIVE_INFINITY;

	/** Drops the ended windows, then, if still full, the live one that ends first. */
	const makeRoom = (at: number): void => {
		let earliestKey: string | undefined;
		let earliestEnd = Number.POSITIVE_INFINITY;
		for (const [key, window] of windows) {
			if (window.resetAt <= at) windows.delete(key);
			else if (window.resetAt < earliestEnd) {
				earliestKey = key;
				earliestEnd = window.resetAt;
			}
		}
		if (windows.size < maxEntries || earliestKey === undefined) return;
		windows.delete(earliestKey);
		unreported += 1;
		if (at - lastWarnAt >= ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS) {
			logger.warn({ evicted: unreported, maxEntries }, "attempt_counter_evicted");
			unreported = 0;
			lastWarnAt = at;
		}
	};

	return {
		async consume(key: string, spec: AttemptSpec): Promise<AttemptCount> {
			if (!isAttemptKey(key)) {
				throw new TypeError(
					"createMemoryAttemptCounter: key must be a non-empty string of at most 512 characters",
				);
			}
			if (!isAttemptSpec(spec)) {
				throw new RangeError(
					"createMemoryAttemptCounter: spec must be { limit, windowSeconds } as positive whole numbers, the window at most a year",
				);
			}
			const { limit, windowSeconds } = spec;
			const at = now();
			if (!Number.isFinite(at)) {
				throw new RangeError("createMemoryAttemptCounter: the clock answered no finite instant");
			}
			const running = windows.get(key);
			if (running !== undefined && running.resetAt > at) {
				if (running.count >= limit) {
					return { allowed: false, remaining: 0, resetAt: new Date(running.resetAt) };
				}
				running.count += 1;
				return {
					allowed: true,
					remaining: limit - running.count,
					resetAt: new Date(running.resetAt),
				};
			}
			if (running !== undefined) windows.delete(key);
			else if (windows.size >= maxEntries) makeRoom(at);
			const resetAt = at + windowSeconds * 1000;
			windows.set(key, { count: 1, resetAt });
			return { allowed: true, remaining: limit - 1, resetAt: new Date(resetAt) };
		},
	};
}
