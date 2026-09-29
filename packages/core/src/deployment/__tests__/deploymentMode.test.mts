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
 * The `deploymentMode` slot (#728): how many replicas the operator says
 * this deployment runs — `single`, `multi`, or `unset` when nothing was
 * said — which core is to fill from its own `core.deployment.mode` for
 * every module that refuses or warns by it. Its contract suite; a test
 * fills the slot with the literal, so there is no double.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { DeploymentMode } from "#/deployment/types.mjs";
import type { ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { deploymentModeContract } from "#/testing/index.mjs";

const RULE = "the mode is single, multi or unset";

/** The names of the cases a mode fails. */
const failing = async (mode: unknown): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of deploymentModeContract({ build: () => mode as DeploymentMode })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

describe("the deploymentMode slot", () => {
	it("is optional, and holds one of the three answers to how many replicas run", () => {
		expectTypeOf<ComponentMap["deploymentMode"]>().toEqualTypeOf<DeploymentMode | undefined>();
		expectTypeOf<
			ProviderDeps<"deploymentMode">["deploymentMode"]
		>().toEqualTypeOf<DeploymentMode>();
		expectTypeOf<DeploymentMode>().toEqualTypeOf<"single" | "multi" | "unset">();
		expect(true).toBe(true);
	});
});

describe("deploymentModeContract", () => {
	it("names its rule", () => {
		expect(deploymentModeContract({ build: () => "single" }).map((c) => c.name)).toEqual([RULE]);
	});

	it.each(["single", "multi", "unset"] as const)("keeps it for %s", async (mode) => {
		expect(await failing(mode)).toEqual([]);
	});

	it("fails it for anything else: another spelling, absence, the configuration's own words", async () => {
		for (const mode of ["Multi", "", undefined, null, "multiple", { mode: "multi" }]) {
			expect(await failing(mode)).toEqual([RULE]);
		}
	});
});
