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
 * The template's posture on session admission (the session-admission ADR's
 * D7): `sessionRequirements.expected` is derived in TypeScript from the
 * PARSED `mfa.mode` — `[]` under `off`, `["mfa"]` otherwise — never from the
 * raw `MFA_MODE`, so a variable the schema refused cannot boot with a
 * posture the config does not carry. `buildModules` installs no module
 * registering `mfa`, so a mode other than `off` is refused at boot by
 * `session-requirement-missing`.
 */

import { BootError } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { withSessionRequirements } from "../buildModules.mjs";
import { type Composition, compose, SINGLE_ENV } from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

describe("sessionRequirements.expected, derived from the parsed mfa.mode (D7)", () => {
	it("declares nothing under the shipped default, off, and boots", async () => {
		current = await compose();
		expect(current.config.sessionRequirements).toEqual({ expected: [] });
	});

	it.each(["optional", "required"] as const)(
		"declares mfa under %s, and is refused at boot while no MFA module registers the requirement: session-requirement-missing",
		async (mode) => {
			const err = await compose({ env: { ...SINGLE_ENV, MFA_MODE: mode } }).then(
				(composition) => {
					current = composition;
					return undefined;
				},
				(caught: unknown) => caught,
			);
			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe("session-requirement-missing");
			expect((err as BootError).details).toMatchObject({ mode, requirement: "mfa" });
		},
	);

	it("withSessionRequirements reads the parsed mode alone: a configuration that says off declares nothing whatever the variable said", () => {
		const off = withSessionRequirements({ mfa: { mode: "off" } } as never);
		expect(off.sessionRequirements).toEqual({ expected: [] });
		const required = withSessionRequirements({ mfa: { mode: "required" } } as never);
		expect(required.sessionRequirements).toEqual({ expected: ["mfa"] });
		// A mode that is none of the three is the schema's to refuse; here it
		// is a RangeError naming the key, never read as off.
		expect(() => withSessionRequirements({ mfa: { mode: "on" } } as never)).toThrow(/mfa\.mode/);
	});
});
