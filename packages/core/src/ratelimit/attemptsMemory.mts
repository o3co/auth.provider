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
 * Full, it drops the windows that have ended and, if still full, evicts in
 * one scan a batch of about one in a hundred of `maxEntries`: the live
 * windows with the fewest attempts, the ones that end first among equals.
 * A key that has spent its limit outlives a flood of fresh keys, and the
 * scan's cost is shared by the batch. It warns `attempt_counter_evicted`
 * (counts and its tag only) at most once a minute. Evicting rather than
 * refusing keeps a flood of fresh keys from locking out every new client.
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
	/** The `tag` on the eviction warning: what the counter counts for. */
	readonly tag?: string;
}

interface Window {
	count: number;
	readonly resetAt: number;
}

/** `a` is evicted before `b`: fewer attempts, then the earlier end. */
const before = (a: Window, b: Window): boolean =>
	a.count < b.count || (a.count === b.count && a.resetAt < b.resetAt);

/**
 * The `size` windows evicted first among those offered, kept in a max-heap
 * whose top is the one evicted last, so one pass selects them in
 * O(n log size).
 */
class Victims {
	readonly #heap: Array<{ readonly key: string; readonly window: Window }> = [];
	readonly #size: number;

	constructor(size: number) {
		this.#size = size;
	}

	offer(key: string, window: Window): void {
		const heap = this.#heap;
		if (heap.length < this.#size) {
			heap.push({ key, window });
			this.#up(heap.length - 1);
			return;
		}
		const top = heap[0];
		if (top !== undefined && before(window, top.window)) {
			heap[0] = { key, window };
			this.#down(0);
		}
	}

	keys(): string[] {
		return this.#heap.map(({ key }) => key);
	}

	#up(index: number): void {
		const heap = this.#heap;
		let i = index;
		while (i > 0) {
			const parent = (i - 1) >> 1;
			const [child, above] = [heap[i], heap[parent]];
			if (child === undefined || above === undefined || !before(above.window, child.window)) return;
			[heap[i], heap[parent]] = [above, child];
			i = parent;
		}
	}

	#down(index: number): void {
		const heap = this.#heap;
		let i = index;
		for (;;) {
			let latest = i;
			for (const child of [2 * i + 1, 2 * i + 2]) {
				const [c, l] = [heap[child], heap[latest]];
				if (c !== undefined && l !== undefined && before(l.window, c.window)) latest = child;
			}
			if (latest === i) return;
			[heap[i], heap[latest]] = [
				heap[latest] as (typeof heap)[number],
				heap[i] as (typeof heap)[number],
			];
			i = latest;
		}
	}
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
	const batch = Math.max(1, Math.floor(maxEntries / 100));
	const tagged = options.tag === undefined ? {} : { tag: options.tag };
	let unreported = 0;
	let lastWarnAt = Number.NEGATIVE_INFINITY;

	/** Drops the ended windows, then, if still full, a batch of the least-counted live ones. */
	const makeRoom = (at: number): void => {
		const victims = new Victims(batch);
		for (const [key, window] of windows) {
			if (window.resetAt <= at) windows.delete(key);
			else victims.offer(key, window);
		}
		if (windows.size < maxEntries) return;
		const evicted = victims.keys();
		for (const key of evicted) windows.delete(key);
		unreported += evicted.length;
		if (at - lastWarnAt >= ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS) {
			logger.warn({ ...tagged, evicted: unreported, maxEntries }, "attempt_counter_evicted");
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
