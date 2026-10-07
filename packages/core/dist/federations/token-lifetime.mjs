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
/** The epoch ms of a real `Date` holding an instant, read by its own value, never through a method it may override. Never throws. */
export const instantOf = (value) => {
    try {
        if (!(value instanceof Date))
            return undefined;
        const ms = Date.prototype.getTime.call(value);
        return Number.isNaN(ms) ? undefined : ms;
    }
    catch {
        return undefined;
    }
};
/** A `Date` for `ms`, or `undefined` outside the Date range (ECMA-262 TimeClip). */
const dateWithin = (ms) => {
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? undefined : date;
};
const readExpiresIn = (value) => {
    if (value === undefined)
        return "silent";
    if (value === null)
        return "none";
    // Its milliseconds must be finite too: 1e306 s is a finite number of seconds.
    return typeof value === "number" && value > 0 && Number.isFinite(value * 1000)
        ? { value }
        : "malformed";
};
const readExpiresAt = (value) => {
    if (value === undefined)
        return "silent";
    if (value === null)
        return "none";
    const ms = instantOf(value);
    return ms === undefined ? "malformed" : { value: ms };
};
/** The largest epoch ms a `Date` holds, either side of the epoch (ECMA-262 §21.4.1.1). */
const MAX_INSTANT_MS = 8.64e15;
/** A primitive finite number: nothing is coerced, and no other type reaches arithmetic that could throw. */
const isFiniteNumber = (value) => typeof value === "number" && Number.isFinite(value);
const assertFiniteInstant = (name, value) => {
    if (!(isFiniteNumber(value) && Math.abs(value) <= MAX_INSTANT_MS)) {
        throw new RangeError(`${name} must be an epoch ms within the Date range`);
    }
};
const assertDuration = (name, value) => {
    if (!(isFiniteNumber(value) && value >= 0)) {
        throw new RangeError(`${name} must be a finite number of ms, at least 0`);
    }
};
/**
 * Read an adapter's `expiresIn` / `expiresAt`. A finite lifetime is dated
 * from `calledAt`, so time the upstream took is not counted as life left:
 * the derived instant is `min(expiresAt, calledAt + expiresIn)`, and
 * `obtainedAt` is `calledAt`. Throws a
 * `RangeError` only for a clock that is not a finite instant, or a floor
 * that is not a finite duration ≥ 0. Each clock field is read once.
 */
export function readUpstreamTokenLifetime(fields, clock) {
    const { calledAt, now, floorMs } = clock;
    assertFiniteInstant("calledAt", calledAt);
    assertFiniteInstant("now", now);
    assertDuration("floorMs", floorMs);
    const expiresIn = readExpiresIn(fields.expiresIn);
    const expiresAt = readExpiresAt(fields.expiresAt);
    if (expiresIn === "malformed" || expiresAt === "malformed")
        return { verdict: "malformed" };
    const lifetime = typeof expiresIn === "object" ? expiresIn.value : undefined;
    const instant = typeof expiresAt === "object" ? expiresAt.value : undefined;
    if (lifetime === undefined && instant === undefined)
        return { verdict: "unstated" };
    if ((lifetime === undefined && expiresIn === "none") ||
        (instant === undefined && expiresAt === "none")) {
        return { verdict: "contradictory" };
    }
    // The earlier of what each stated field names; an absent one names no bound.
    const derived = dateWithin(Math.min(instant ?? Number.POSITIVE_INFINITY, calledAt + (lifetime === undefined ? Number.POSITIVE_INFINITY : lifetime * 1000)));
    if (derived === undefined)
        return { verdict: "malformed" };
    const remainingMs = derived.getTime() - now;
    if (remainingMs <= 0 || remainingMs < floorMs || derived.getTime() <= calledAt) {
        return { verdict: "spent" };
    }
    const obtainedAt = new Date(calledAt);
    if (lifetime === undefined) {
        return { verdict: "finite", stated: "expiresAt", obtainedAt, expiresAt: derived };
    }
    return {
        verdict: "finite",
        stated: instant === undefined ? "expiresIn" : "both",
        obtainedAt,
        expiresAt: derived,
        issuedLifetime: lifetime,
    };
}
/** A fresh object each time: a caller that changes one cannot make another token believed. */
const unbelieved = () => ({
    believed: false,
    remainingMs: 0,
    halfSpent: true,
});
/**
 * The age of a token held since `obtainedAt`. One dated ahead of `now` by
 * up to `allowanceMs` (a refresh buffer, or replicas' clock skew) is
 * believed; one dated further ahead, or not before its own end, is not, and
 * reads as ended. Throws a `RangeError` only for a clock that is not a
 * finite instant, or an allowance that is not a finite duration ≥ 0. Each
 * clock field is read once.
 */
export function judgeHeldUpstreamToken(token, at) {
    const { now, allowanceMs } = at;
    assertFiniteInstant("now", now);
    assertDuration("allowanceMs", allowanceMs);
    const obtainedAt = instantOf(token.obtainedAt);
    const expiresAt = instantOf(token.expiresAt);
    if (obtainedAt === undefined || expiresAt === undefined || obtainedAt >= expiresAt) {
        return unbelieved();
    }
    const age = now - obtainedAt;
    if (age < -allowanceMs)
        return unbelieved();
    const lifetimeMs = expiresAt - obtainedAt;
    return {
        believed: true,
        remainingMs: Math.min(obtainedAt, now) + lifetimeMs - now,
        halfSpent: age >= lifetimeMs / 2,
    };
}
