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
 * `mfa.mode` as a consumer reads it (the MFA ADR's D19; the session-admission
 * ADR's D7): the boot check that refuses a mode other than `off` while no
 * requirement named `mfa` is registered (`session-requirement-missing`), and
 * the MFA package, whose requirement is the mode's one reader at request
 * time. No consumer of a session reads it: what "logged in" means under a
 * mode is the requirement's to decide, through admission.
 */

/**
 * `mfa.mode` (D19): `required` — every password login has a second factor and
 * every consumer enforces it; `optional` — users with factors are challenged,
 * nobody is forced, step-up works; `off` — no MFA.
 */
export type MfaMode = "off" | "optional" | "required";

/**
 * `mfa.mode` as a consumer reads it, off any config-shaped value: the mode, or
 * `undefined` when it is absent — which only absence is. What absence means is
 * the caller's to decide: core's schema and reference default it to `"off"`
 * (D19). A value that is given but is not one of the three — a typo, a casing
 * slip, `""`, `null` — is a `RangeError` naming `mfa.mode` and quoting
 * nothing of the value, never `undefined`: read as absent, a typo would
 * default to `"off"` and switch MFA off. Core's schema refuses such a value
 * at boot; this refuses it in a hand-built configuration too.
 */
export function readMfaMode(config: unknown): MfaMode | undefined {
	const mode = (config as { mfa?: { mode?: unknown } } | undefined)?.mfa?.mode;
	if (mode === undefined) return undefined;
	if (mode === "off" || mode === "optional" || mode === "required") return mode;
	throw new RangeError('mfa.mode must be "off", "optional" or "required"');
}
