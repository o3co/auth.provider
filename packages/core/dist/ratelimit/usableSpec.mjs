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
import { isStorableLifetime } from "../adapters/expiry.mjs";
const isPositiveInteger = (value) => typeof value === "number" && Number.isInteger(value) && value > 0;
/**
 * Whether a value is a spec a limiter can apply as written: a positive whole
 * `limit`, and a positive whole `windowSeconds` that ends within ECMAScript's
 * Date range (core's `isStorableLifetime`).
 *
 * Each refusal is a budget that is not the one written. A zero window is an
 * `EXPIRE key 0`, which deletes the counter, and an in-process bucket that
 * resets on every check: it never limits anything. A limit of zero or less
 * denies everything. NaN and fractions are not budgets. A window past the Date
 * range has no end any clock reaches: Redis refuses the `EXPIRE` after its
 * `INCR` has run (#269's shape), and an in-process bucket would reset at an
 * Invalid Date.
 */
export const isUsableRateLimitSpec = (value) => {
    if (typeof value !== "object" || value === null)
        return false;
    const { limit, windowSeconds } = value;
    return (isPositiveInteger(limit) &&
        isPositiveInteger(windowSeconds) &&
        isStorableLifetime(windowSeconds * 1000));
};
/**
 * A value as a refusal shows it, with its type: a string quoted, a number as
 * it prints (`NaN` included), a BigInt with its `n`, a function as
 * `[function]` (never its source), anything else as JSON. `String()` showed
 * the string "20" as 20, which read as a refusal of a usable number. What
 * JSON cannot write — a circular object, one whose `toJSON` answers nothing,
 * a Symbol — falls back to `String()`, so the refusal is still given.
 */
export const shownConfigValue = (value) => {
    switch (typeof value) {
        case "number":
        case "undefined":
        case "symbol":
            return String(value);
        case "string":
            return JSON.stringify(value);
        case "bigint":
            return `${value}n`;
        case "function":
            return "[function]";
    }
    try {
        return JSON.stringify(value) ?? String(value);
    }
    catch {
        return String(value);
    }
};
const described = (spec) => {
    if (typeof spec !== "object" || spec === null)
        return shownConfigValue(spec);
    const { limit, windowSeconds } = spec;
    return `limit ${shownConfigValue(limit)}, windowSeconds ${shownConfigValue(windowSeconds)}`;
};
/**
 * What `z.coerce.number()` makes of a configured value, for a key whose
 * owning schema coerces: a number as it is, and a string that is not blank
 * and whose `Number()` is finite as that number. HOCON substitutes an
 * environment variable as a string, so a key filled from one arrives as one
 * wherever the schema did not run. Anything else — a blank or non-numeric
 * string, a boolean, an array, an object — is `undefined`: none of it can
 * come from a substitution, and none of it is a number.
 */
export const configuredNumber = (value) => {
    if (typeof value === "number")
        return value;
    if (typeof value !== "string" || value.trim() === "")
        return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
};
/**
 * The budget a configuration gives under `key`, or a `RangeError` naming
 * `key` when it is given but is not a spec a limiter can apply.
 *
 * For a seed and anything else that reads a budget from its own config key
 * (`oauth.deviceAuthorization.rateLimit`,
 * `webauthn.rateLimit.authenticationOptions`). Each field is read as the
 * key's schema coerces it, so a numeric string is its number. A key that was given is a
 * configuration someone wrote, a hand-built one included, so it is refused
 * rather than skipped: skipped, the route ran on the limiter's default
 * instead. The message names the key and says what it must be, not which
 * limiter would have refused it. A key that was not given is the caller's
 * to handle: it is not a refusal.
 */
export function requireUsableConfiguredRateLimitSpec(key, value) {
    const spec = readConfiguredRateLimitSpec(value);
    if (spec === undefined) {
        throw new RangeError(`${key} must be { limit, windowSeconds } as positive whole numbers, with a window that ends within the Date range (got ${described(value)})`);
    }
    return spec;
}
/**
 * A configured `{ limit, windowSeconds }` budget, read as the key's owning
 * schema reads it (`configuredNumber`, so a numeric string is its number)
 * and judged by the one predicate; `undefined` when it is not one a limiter
 * can apply. The adapters' own `limits` take no such reading: their schemas
 * do not coerce, and neither do they.
 */
export const readConfiguredRateLimitSpec = (value) => {
    if (typeof value !== "object" || value === null)
        return undefined;
    const { limit, windowSeconds } = value;
    const spec = { limit: configuredNumber(limit), windowSeconds: configuredNumber(windowSeconds) };
    return isUsableRateLimitSpec(spec)
        ? { limit: spec.limit, windowSeconds: spec.windowSeconds }
        : undefined;
};
/**
 * Refuses, when a limiter is built, every spec it was given that
 * {@link isUsableRateLimitSpec} does not accept: each entry of `limits`, and
 * `defaultLimit`. `undefined` is "not given", and nothing else is.
 *
 * Refused, never dropped. A dropped spec let the adapter's default budget
 * apply in its place, a looser one than the operator wrote. On the device
 * verification route that is the budget RFC 8628 §5.1 sizes the user code
 * against. Every adapter calls this, so one configuration is one budget,
 * whichever adapter is mounted. The zod schemas refuse the same values at the
 * config boundary; this is for the builder paths and the hand-built configs
 * that never pass them.
 */
export function assertUsableRateLimitSpecs(who, specs) {
    const refuse = (name, spec) => {
        throw new RangeError(`${who}: ${name} must be { limit, windowSeconds } as positive whole numbers, with a window that ends within the Date range (got ${described(spec)})`);
    };
    const { limits, defaultLimit } = specs;
    if (limits !== undefined) {
        if (typeof limits !== "object" || limits === null || Array.isArray(limits)) {
            throw new RangeError(`${who}: limits must be an object of { limit, windowSeconds } specs, keyed by prefix (got ${Array.isArray(limits) ? "an array" : String(limits)})`);
        }
        for (const [prefix, spec] of Object.entries(limits)) {
            if (!isUsableRateLimitSpec(spec))
                refuse(`limits.${prefix}`, spec);
        }
    }
    if (defaultLimit !== undefined && !isUsableRateLimitSpec(defaultLimit)) {
        refuse("defaultLimit", defaultLimit);
    }
}
