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
 * `coreConfigForTests`, on core's testing entry: core's own section, `core`,
 * as a configuration fragment another package's tests lay over theirs, so
 * none writes core's keys by hand.
 */

import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { deploymentModeOf } from "#/deployment/mode.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "#/testing/index.mjs";

describe("coreConfigForTests", () => {
	it("declares that the composition expects no session requirement, and states no deployment mode, by default", () => {
		const fragment = coreConfigForTests();
		expect(Object.keys(fragment)).toEqual(["core"]);
		const config = { ...makeValidCoreConfig(), ...fragment };
		expect(CoreConfigSchema.parse(config).core).toEqual({
			sessionRequirements: { expected: [] },
		});
		expect(deploymentModeOf(config)).toBe("unset");
	});

	it("declares the requirements it is given, and the deployment mode, as core reads them", () => {
		for (const mode of ["single", "multi"] as const) {
			const config = {
				...makeValidCoreConfig(),
				...coreConfigForTests({ expected: ["mfa", "extra"], deploymentMode: mode }),
			};
			expect(CoreConfigSchema.parse(config).core?.sessionRequirements).toEqual({
				expected: ["mfa", "extra"],
			});
			expect(deploymentModeOf(config)).toBe(mode);
		}
	});

	it("is what the valid fixture declares", () => {
		expect(makeValidCoreConfig().core).toEqual(coreConfigForTests().core);
	});

	it("answers a fresh copy each call: a caller's change stays its own", () => {
		const first = coreConfigForTests({ expected: ["mfa"] });
		first.core.sessionRequirements.expected.push("changed");
		expect(coreConfigForTests({ expected: ["mfa"] }).core.sessionRequirements.expected).toEqual([
			"mfa",
		]);
	});
});
