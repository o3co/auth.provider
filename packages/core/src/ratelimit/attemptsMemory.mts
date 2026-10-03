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
 * so a limit it enforces is per replica. Anyone who can reach a guarded route
 * drives its writes, so it holds at most `maxEntries` keys and, full, refuses
 * a new key as a store fault (the guard answers `503`) rather than evict a
 * live window, which would hand that window's key a fresh limit.
 */

import { usableMaxEntries } from "../single-use/max-entries.mjs";
import {
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	isAttemptKey,
	isAttemptSpec,
} from "./attempts.mjs";

export const DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES = 100_000;

export interface MemoryAttemptCounterOptions {
	/** The most keys it holds a window for. Default {@link DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES}. */
	readonly maxEntries?: number;
	/** Epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
}

/** A new key refused because every key the counter holds has a window running. */
export class MemoryAttemptCounterFullError extends Error {
	override readonly name = "MemoryAttemptCounterFullError";
	constructor(maxEntries: number) {
		super(`in-process attempt counter is full: ${maxEntries} keys have a window running`);
	}
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
	const windows = new Map<string, Window>();
	// No window held ends before this: until then a full counter has no room
	// to make, and refuses without a scan.
	let earliestEnd = Number.NEGATIVE_INFINITY;

	const makeRoom = (at: number): boolean => {
		if (windows.size < maxEntries) return true;
		if (at < earliestEnd) return false;
		let earliest = Number.POSITIVE_INFINITY;
		for (const [key, window] of windows) {
			if (window.resetAt <= at) windows.delete(key);
			else if (window.resetAt < earliest) earliest = window.resetAt;
		}
		earliestEnd = earliest;
		return windows.size < maxEntries;
	};

	return {
		async consume(key: string, spec: AttemptSpec): Promise<AttemptCount> {
			if (!isAttemptKey(key)) {
				throw new TypeError("createMemoryAttemptCounter: key must be a non-empty string");
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
			else if (!makeRoom(at)) throw new MemoryAttemptCounterFullError(maxEntries);
			const resetAt = at + windowSeconds * 1000;
			windows.set(key, { count: 1, resetAt });
			if (resetAt < earliestEnd) earliestEnd = resetAt;
			return { allowed: true, remaining: limit - 1, resetAt: new Date(resetAt) };
		},
	};
}
