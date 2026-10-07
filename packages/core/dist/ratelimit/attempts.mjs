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
import { instantOf } from "../federations/token-lifetime.mjs";
const isPositiveSafeInteger = (value) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
/**
 * The longest window a counter takes. Verifier windows are minutes; the cap
 * lets a reader bound a window's end without knowing the spec it started under.
 */
export const MAX_ATTEMPT_WINDOW_SECONDS = 86_400;
/** A spec a counter takes: a positive whole `limit` and a positive whole `windowSeconds` of at most {@link MAX_ATTEMPT_WINDOW_SECONDS}. */
export const isAttemptSpec = (value) => {
    if (typeof value !== "object" || value === null)
        return false;
    const { limit, windowSeconds } = value;
    return (isPositiveSafeInteger(limit) &&
        isPositiveSafeInteger(windowSeconds) &&
        windowSeconds <= MAX_ATTEMPT_WINDOW_SECONDS);
};
/** The longest key a counter takes. */
export const MAX_ATTEMPT_KEY_LENGTH = 512;
/** A key a counter takes: a non-empty string of at most {@link MAX_ATTEMPT_KEY_LENGTH} characters. */
export const isAttemptKey = (value) => typeof value === "string" && value.length > 0 && value.length <= MAX_ATTEMPT_KEY_LENGTH;
/** How far a counter's clock may stand from the reader's when its window's end is judged. */
export const ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS = 5_000;
/**
 * A counter's answer, read at `nowMs`, as a fresh, frozen count, each field
 * read once, or `undefined` when it is not one under `spec`: `allowed` not a
 * boolean, `remaining` not a whole number below `spec.limit` on an allowed
 * attempt or 0 on a refused one, `resetAt` not a valid `Date` within
 * {@link ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS} of `[nowMs, nowMs + MAX_ATTEMPT_WINDOW_SECONDS]`,
 * or a read that throws. The bound is the longest window any spec allows, not
 * the current spec's, so a window started under an earlier, longer spec is
 * still a count.
 */
export function readAttemptCount(answer, spec, nowMs) {
    let allowed;
    let remaining;
    let resetAt;
    try {
        if (typeof answer !== "object" || answer === null)
            return undefined;
        ({ allowed, remaining, resetAt } = answer);
    }
    catch {
        return undefined;
    }
    if (typeof allowed !== "boolean")
        return undefined;
    if (typeof remaining !== "number" || !Number.isSafeInteger(remaining) || remaining < 0) {
        return undefined;
    }
    if (allowed ? remaining >= spec.limit : remaining !== 0)
        return undefined;
    const resetMs = instantOf(resetAt);
    if (resetMs === undefined || !Number.isFinite(nowMs))
        return undefined;
    if (resetMs < nowMs - ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS ||
        resetMs > nowMs + MAX_ATTEMPT_WINDOW_SECONDS * 1000 + ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS) {
        return undefined;
    }
    return Object.freeze({ allowed, remaining, resetAt: new Date(resetMs) });
}
