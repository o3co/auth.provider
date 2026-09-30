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

/**
 * A value as a refusal shows it, with its type: a string quoted (so `"20"`
 * does not read as a usable number), a number as it prints (`NaN` included),
 * a BigInt with its `n`, a function as `[function]` (never its source),
 * anything else as JSON, or `String()` where JSON cannot write it (a circular
 * object, a `toJSON` that answers nothing, a Symbol).
 */
export const shownConfigValue = (value: unknown): string => {
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
	} catch {
		return String(value);
	}
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
export const configuredNumber = (value: unknown): number | undefined => {
	if (typeof value === "number") return value;
	if (typeof value !== "string" || value.trim() === "") return undefined;
	const parsed = Number(value);
	return Number.isFinite(parsed) ? parsed : undefined;
};
