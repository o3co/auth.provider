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
 * The admission actions the MFA package's routes admit, declared with their
 * grades before those routes exist, and registered by no module until a route
 * admits one: a module registers only what its own code admits.
 */

import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { MFA_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { mfaModule, mfaModules } from "#/module.mjs";

describe("the MFA package's admission actions", () => {
	it("declare mfa.manage, graded credential_change", () => {
		expect(MFA_ADMISSION_ACTIONS).toEqual({ "mfa.manage": { grade: "credential_change" } });
		expect(Object.isFrozen(MFA_ADMISSION_ACTIONS)).toBe(true);
	});

	it("register as core registers a module's actions: names in its grammar, grades a module may declare", () => {
		const resolver = resolverForTests([], { actions: MFA_ADMISSION_ACTIONS });
		expect(resolver.action("mfa.manage")).toEqual({
			name: "mfa.manage",
			grade: "credential_change",
		});
	});

	it("are registered by no MFA module yet: no route of the package admits a session", () => {
		for (const module of [mfaModule(), ...mfaModules()]) {
			expect(module.contributes?.admissionActions, module.name).toBeUndefined();
		}
	});
});
