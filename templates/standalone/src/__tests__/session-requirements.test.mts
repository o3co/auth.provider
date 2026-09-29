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
 * D7): its `config/application.conf` expects no session requirement
 * (`sessionRequirements.expected = []`), because `buildModules` installs no
 * module that registers one. A deployment that adds such a module names its
 * requirement there. `mfa.mode` changes nothing the template boots: no module
 * it installs reads the key.
 */

import { BootError } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { readOwnLayers, resolveLayers } from "../configPath.mjs";
import {
	type Composition,
	compose,
	ownFiles,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** The boot's refusal, or `undefined` when it booted (kept for disposal). */
const refusal = (composing: Promise<Composition>): Promise<unknown> =>
	composing.then(
		(composition) => {
			current = composition;
			return undefined;
		},
		(caught: unknown) => caught,
	);

describe("the template's sessionRequirements.expected", () => {
	it("is [] in the shipped configuration, and the composition boots with it", async () => {
		const own = readOwnLayers(ownFiles(), { env: SINGLE_ENV });
		expect(resolveLayers(own, []).sessionRequirements).toEqual({ expected: [] });
		current = await compose();
		expect(current.config.sessionRequirements).toEqual({ expected: [] });
		expect([...(current.handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual(
			[],
		);
	});

	it.each(["optional", "required"] as const)(
		"boots under MFA_MODE=%s, expecting no requirement: no module the template installs reads mfa.mode",
		async (mode) => {
			current = await compose({ env: { ...SINGLE_ENV, MFA_MODE: mode } });
			expect(current.config.mfa.mode).toBe(mode);
			expect(current.config.sessionRequirements).toEqual({ expected: [] });
		},
	);

	it("refuses the boot when the configuration expects mfa and no installed module registers it: session-requirement-missing, naming the key and the name", async () => {
		const err = await refusal(
			compose({ config: (config) => ({ ...config, sessionRequirements: { expected: ["mfa"] } }) }),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			configKey: "sessionRequirements.expected",
			missing: ["mfa"],
		});
	});
});
