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
 * grades, and registered by no module on the package's entry: a module
 * registers only what its own code admits.
 */

import type { Module } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { MFA_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import * as entry from "#/index.mjs";

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

	it("are registered by no module on the package's entry", () => {
		const isModule = (value: unknown): value is Module =>
			typeof value === "object" && value !== null && typeof (value as Module).name === "string";
		const modules = [
			...Object.values(entry).filter(isModule),
			entry.mfaModule(),
			...entry.mfaModules(),
		];
		expect(modules.map((module) => module.name).sort()).toEqual([
			"mfa",
			"mfa",
			"mfa-recovery-code-factor",
			"mfa-recovery-code-factor",
			"mfa-totp-factor",
			"mfa-totp-factor",
		]);
		for (const module of modules) {
			expect(module.contributes?.admissionActions, module.name).toBeUndefined();
		}
	});
});
