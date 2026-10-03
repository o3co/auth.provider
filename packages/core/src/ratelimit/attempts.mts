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
 * The `AttemptCounter` port: the counter behind a verifier's own attempt
 * limits, the `attemptCounter` slot's value. It counts; the limit it counts
 * against is handed in on every call by the module that owns it, so no
 * deployment configuration can loosen it. It is not a `RateLimiter`, whose
 * budgets and outage policy are the deployment's.
 *
 * Also the port's vocabulary: which specs and keys a counter takes, and the
 * one reading of its answer (`readAttemptCount`).
 */

import { MAX_DURATION_SECONDS } from "../config/durations.mjs";
import { instantOf } from "../federations/token-lifetime.mjs";

/** The limit one consume is counted against: at most `limit` attempts in a window of `windowSeconds`. */
export interface AttemptSpec {
	readonly limit: number;
	readonly windowSeconds: number;
}

/** A counter's answer to one attempt. */
export interface AttemptCount {
	/** This attempt is one of the first `limit` counted under its key in its window. */
	readonly allowed: boolean;
	/** Attempts the key has left in the window after this one: below `limit` when allowed, 0 when refused. */
	readonly remaining: number;
	/** When the window this attempt fell in ends. */
	readonly resetAt: Date;
}

/**
 * A fixed-window attempt counter.
 *
 * `consume` counts one attempt under `key`, atomically: of the attempts made
 * under one key in one window, by any number of callers or replicas, exactly
 * the first `spec.limit` are allowed, each against the spec handed in with
 * it, and a refused attempt counts nothing. A window starts at the first
 * attempt counted under a key with no window running, and ends
 * `spec.windowSeconds` later; a window keeps its end when a later spec
 * changes the window. Keys are counted apart.
 *
 * It rejects, counting nothing, a key `isAttemptKey` refuses or a spec
 * `isAttemptSpec` refuses. A backend that cannot count rejects: an outage is
 * never answered as a count.
 */
export interface AttemptCounter {
	consume(key: string, spec: AttemptSpec): Promise<AttemptCount>;
}

const isPositiveSafeInteger = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value > 0;

/** A spec a counter takes: a positive whole `limit` and a positive whole `windowSeconds` of at most a year. */
export const isAttemptSpec = (value: unknown): value is AttemptSpec => {
	if (typeof value !== "object" || value === null) return false;
	const { limit, windowSeconds } = value as { limit?: unknown; windowSeconds?: unknown };
	return (
		isPositiveSafeInteger(limit) &&
		isPositiveSafeInteger(windowSeconds) &&
		windowSeconds <= MAX_DURATION_SECONDS
	);
};

/** The longest key a counter takes. */
export const MAX_ATTEMPT_KEY_LENGTH = 512;

/** A key a counter takes: a non-empty string of at most {@link MAX_ATTEMPT_KEY_LENGTH} characters. */
export const isAttemptKey = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0 && value.length <= MAX_ATTEMPT_KEY_LENGTH;

/** How far a counter's clock may stand from the reader's when its window's end is judged. */
export const ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS = 5_000;

/** The least horizon a window's end is read within, so a window shortened on a shared store mid-window is still a count. */
const MIN_RESET_HORIZON_SECONDS = 86_400;

/**
 * A counter's answer, read at `nowMs`, as a fresh, frozen count, each field
 * read once, or `undefined` when it is not one under `spec`: `allowed` not a
 * boolean, `remaining` not a whole number below `spec.limit` on an allowed
 * attempt or 0 on a refused one, `resetAt` not a valid `Date` within
 * {@link ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS} of `[nowMs, nowMs + max(windowSeconds,
 * one day)]`, or a read that throws. The day keeps a window started under an
 * earlier, longer spec a count rather than an outage.
 */
export function readAttemptCount(
	answer: unknown,
	spec: AttemptSpec,
	nowMs: number,
): AttemptCount | undefined {
	let allowed: unknown;
	let remaining: unknown;
	let resetAt: unknown;
	try {
		if (typeof answer !== "object" || answer === null) return undefined;
		({ allowed, remaining, resetAt } = answer as Record<string, unknown>);
	} catch {
		return undefined;
	}
	if (typeof allowed !== "boolean") return undefined;
	if (typeof remaining !== "number" || !Number.isSafeInteger(remaining) || remaining < 0) {
		return undefined;
	}
	if (allowed ? remaining >= spec.limit : remaining !== 0) return undefined;
	const resetMs = instantOf(resetAt);
	if (resetMs === undefined || !Number.isFinite(nowMs)) return undefined;
	if (
		resetMs < nowMs - ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS ||
		resetMs >
			nowMs +
				Math.max(spec.windowSeconds, MIN_RESET_HORIZON_SECONDS) * 1000 +
				ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS
	) {
		return undefined;
	}
	return Object.freeze({ allowed, remaining, resetAt: new Date(resetMs) });
}

// ---------------------------------------------------------------------------
// ComponentMap slot: `attemptCounter`, the counter a verifier's attempt guard
// runs on. Optional: without one, `createAttemptGuard` counts per process
// where the deployment mode allows it.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly attemptCounter?: AttemptCounter;
	}
}
