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
 * What an identifier this server looks something up by must look like: a
 * `client_id`, a JWT `kid`, an assertion's `iss`.
 *
 * Each arrives before anything vouches for it and goes to a store or keystore
 * a deployment may have written, one that may throw on input it cannot
 * handle, which would read as that store's outage (`503`). So it is screened
 * first, and a failing value is refused as naming nothing, without a lookup.
 * Configured kids and registered clients are held to the same rule, so every
 * value this server hands out is one it will look up again.
 *
 * The rule: a non-empty string of at most {@link MAX_IDENTIFIER_LENGTH}
 * characters with no C0 (`U+0000`–`U+001F`), DEL or C1 (`U+0080`–`U+009F`)
 * control character. RFC 6749 Appendix A.1 makes `client_id` `*VSCHAR`;
 * non-ASCII is not refused, since a registry may already hold it.
 */

/**
 * The longest identifier this server looks up. No specification bounds a
 * `client_id`, a `kid` or an issuer; the ones this server meets are
 * operator-chosen names and `https` URLs, far shorter in practice. 256 is
 * past all of them, and small enough that a store is never handed an
 * unbounded, attacker-chosen value.
 */
export const MAX_IDENTIFIER_LENGTH = 256;

// biome-ignore lint/suspicious/noControlCharactersInRegex: finding control characters is the point of this check.
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/** Whether `value` is a well-formed identifier (see the module comment). */
export function isWellFormedIdentifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= MAX_IDENTIFIER_LENGTH &&
		!CONTROL_CHARACTER.test(value)
	);
}

/**
 * What is wrong with an identifier {@link isWellFormedIdentifier} refuses,
 * for a configuration error. Never the value itself: it may carry control
 * characters, which a terminal or a log viewer would act on.
 */
export function describeMalformedIdentifier(value: unknown): string {
	if (typeof value !== "string") return `a ${value === null ? "null" : typeof value}, not a string`;
	if (value.length === 0) return "empty";
	if (value.length > MAX_IDENTIFIER_LENGTH)
		return `${value.length} characters, more than ${MAX_IDENTIFIER_LENGTH}`;
	return "a string carrying a control character";
}
