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
 * How a configured value is read where its owning schema did not run, and
 * how a refusal quotes it.
 */
import { z } from "zod";
import { wholeNumberFromEnv } from "./application.schema.mjs";
/**
 * A value as a refusal shows it, with its type: a string quoted (so `"20"`
 * does not read as a usable number), a number as it prints (`NaN` included),
 * a BigInt with its `n`, a function as `[function]` (never its source),
 * anything else as JSON, or `String()` where JSON cannot write it (a circular
 * object, a `toJSON` that answers nothing, a Symbol).
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
/** A number, or a string of decimal digits read as its number. */
const numberOrDecimalDigits = wholeNumberFromEnv(z.number());
/**
 * A configured number as core's schemas read one ({@link wholeNumberFromEnv}),
 * for a key read where its owning schema did not run: a number as it is, and
 * a string of decimal digits (whitespace around allowed) as its number. HOCON
 * substitutes an environment variable as a string, so a key filled from one
 * arrives as one. Anything else — a blank string, a hex, exponent, sign or
 * fraction, a boolean, an array, an object — is `undefined`, never a number
 * the operator did not write. The caller judges the range.
 */
export const configuredNumber = (value) => {
    if (typeof value === "number")
        return value;
    const read = numberOrDecimalDigits.safeParse(value);
    return read.success ? read.data : undefined;
};
