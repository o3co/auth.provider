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
 * The contract suite of the `deploymentMode` slot, which core alone fills:
 * `deploymentModeContract(input)` holds the value to its three answers —
 * `single`, `multi`, or `unset` when the operator said nothing. There is no
 * double: a test fills the slot with the literal.
 */

import assert from "node:assert/strict";
import type { DeploymentMode } from "#/deployment/types.mjs";
import type { ContractCase } from "#/session-admission/testing/requirement.contract.mjs";

export interface DeploymentModeContractInput {
	/** The mode under test: what core fills the slot with, from the configuration its test chose. */
	readonly build: () => DeploymentMode;
}

const MODES: ReadonlySet<unknown> = new Set<DeploymentMode>(["single", "multi", "unset"]);

/** The cases of the `deploymentMode` contract over the mode `input` builds. */
export function deploymentModeContract(
	input: DeploymentModeContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "the mode is single, multi or unset",
			run: async () => {
				const mode = build();
				assert.ok(
					MODES.has(mode),
					`${JSON.stringify(mode)} is not single, multi or unset: absence is "unset", never undefined`,
				);
			},
		},
	];
}
