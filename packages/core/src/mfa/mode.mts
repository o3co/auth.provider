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
 * `mfa.mode` as the standalone template reads it before it knows its modules,
 * to declare `mfa` in `sessionRequirements.expected` when the mode is not
 * `off`. The MFA module, the mode's one request-time reader, reads it from its
 * own section, whose schema admits the same three values. Boot validates the
 * value, and its checks do not act on it: they check
 * `sessionRequirements.expected`. Session consumers never read it; admission
 * decides what "logged in" means (ADR 2026-09-28-session-admission).
 */

/**
 * `mfa.mode`, as the MFA module honours it; without that module no mode is
 * honoured. `required`: every password login has a second factor and every
 * consumer enforces it. `optional`: users with factors are challenged, nobody
 * is forced, step-up works. `off`: no MFA, and the MFA module refuses it —
 * installed is on.
 */
export type MfaMode = "off" | "optional" | "required";

/**
 * Reads `mfa.mode` off any config-shaped value: the mode, or `undefined` only
 * when absent (core's schema defaults it to `"off"`). Any other given value
 * (a typo, a casing slip, `""`, `null`) is a `RangeError` that quotes nothing of
 * the value, never `undefined`: read as absent, a typo would switch MFA off.
 * This also covers hand-built configurations the schema never sees.
 */
export function readMfaMode(config: unknown): MfaMode | undefined {
	const mode = (config as { mfa?: { mode?: unknown } } | undefined)?.mfa?.mode;
	if (mode === undefined) return undefined;
	if (mode === "off" || mode === "optional" || mode === "required") return mode;
	throw new RangeError('mfa.mode must be "off", "optional" or "required"');
}
