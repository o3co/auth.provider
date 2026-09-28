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
 * `mfa.mode` as a consumer reads it (the MFA ADR's D19): the boot check that
 * refuses `mfa.mode` without a requirement named `mfa` (the session-admission
 * ADR's D7), and the MFA package once it exists.
 */

import { describe, expect, it } from "vitest";
import { readMfaMode } from "#/mfa/mode.mjs";

describe("readMfaMode — `mfa.mode` as a consumer reads it", () => {
	it.each(["off", "optional", "required"] as const)("reads %s", (mode) => {
		expect(readMfaMode({ mfa: { mode } })).toBe(mode);
	});

	it.each([
		["no config", undefined],
		["no mfa section", {}],
		["no mode", { mfa: {} }],
	])("answers undefined for %s: absent, for the caller to default", (_label, config) => {
		expect(readMfaMode(config)).toBeUndefined();
	});

	it.each([
		["a mode it does not know", { mfa: { mode: "maybe" } }],
		["a typo", { mfa: { mode: "requried" } }],
		["a casing slip", { mfa: { mode: "Required" } }],
		["an empty string", { mfa: { mode: "" } }],
		["null", { mfa: { mode: null } }],
		["a non-string", { mfa: { mode: true } }],
	])(
		"refuses %s with a RangeError naming mfa.mode: a given but unusable mode is never read as off",
		(_label, config) => {
			// Read as absent, a typo would default to "off" and switch MFA off —
			// failing open once a consumer enforces the mode.
			expect(() => readMfaMode(config)).toThrow(RangeError);
			expect(() => readMfaMode(config)).toThrow(/mfa\.mode/);
		},
	);

	it("quotes nothing of the value it refuses", () => {
		let refusal: unknown;
		try {
			readMfaMode({ mfa: { mode: "sentinel-value" } });
		} catch (err) {
			refusal = err;
		}
		expect(refusal).toBeInstanceOf(RangeError);
		expect((refusal as RangeError).message).not.toContain("sentinel-value");
	});
});
