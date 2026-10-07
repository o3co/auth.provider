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
 * The contract suite of the `federationGrantPolicy` slot.
 * `federationGrantPolicyContract(input)` holds the policy to its two
 * switches, resolved to booleans, no allowance to keep grants while grants
 * are off, the whole frozen. The slot's test double,
 * `createTestFederationGrantPolicy`, is core's, on its testing entry.
 */

import assert from "node:assert/strict";
import type { FederationGrantPolicy } from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";
import { unfrozenPath } from "../unfrozenPath.mjs";

export interface FederationGrantPolicyContractInput {
	/** The policy under test, built afresh for each case: a provider's, over the configuration its test chose. */
	readonly build: () => FederationGrantPolicy;
}

/** A switch's case: it is resolved to true or false. */
const resolvedSwitch = (
	build: () => FederationGrantPolicy,
	name: keyof FederationGrantPolicy,
): ContractCase => ({
	name: `${name} is true or false`,
	run: async () => {
		const value: unknown = build()[name];
		assert.equal(
			typeof value,
			"boolean",
			`${name} must be resolved to true or false, never left absent or as the string an environment variable carries (got ${String(value)})`,
		);
	},
});

/** The cases of the `federationGrantPolicy` contract over the policy `input` builds. */
export function federationGrantPolicyContract(
	input: FederationGrantPolicyContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		resolvedSwitch(build, "enabled"),
		resolvedSwitch(build, "allowKeepOnSubjectRevocation"),
		{
			name: "allowKeepOnSubjectRevocation is false while grants are off",
			run: async () => {
				const { enabled, allowKeepOnSubjectRevocation } = build();
				assert.ok(
					enabled !== false || allowKeepOnSubjectRevocation !== true,
					"allowKeepOnSubjectRevocation is true while enabled is false: an allowance to keep grants a deployment does not have is an allowance over nothing, and a reader reads the member alone",
				);
			},
		},
		{
			name: "the policy is frozen",
			run: async () => {
				const found = unfrozenPath(build(), "the policy");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the policy could change it under the others`,
				);
			},
		},
	];
}
