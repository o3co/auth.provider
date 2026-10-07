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
 * The contract suite of the `tokenBindingSettings` slot, which core alone
 * fills. `tokenBindingSettingsContract(input)` holds the settings to what
 * core's reader of `core.tokenBinding` answers: a dispatch policy core
 * arbitrates by, a boolean for the confidential-client rule, the whole frozen.
 */

import assert from "node:assert/strict";
import type { DispatchPolicy, TokenBindingSettings } from "#/middleware/tokenBinding.mjs";
import type { ContractCase } from "#/session-admission/testing/requirement.contract.mjs";
import { unfrozenPath } from "#/testing/slots/shared.mjs";

export interface TokenBindingSettingsContractInput {
	/** The settings under test: what core fills the slot with, from the configuration its test chose. */
	readonly build: () => TokenBindingSettings;
}

const POLICIES: ReadonlySet<unknown> = new Set<DispatchPolicy>([
	"intent-explicit",
	"strict-mutual-exclusion",
]);

/** The cases of the `tokenBindingSettings` contract over the settings `input` builds. */
export function tokenBindingSettingsContract(
	input: TokenBindingSettingsContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "dispatchPolicy is intent-explicit or strict-mutual-exclusion",
			run: async () => {
				const { dispatchPolicy } = build();
				assert.ok(
					POLICIES.has(dispatchPolicy),
					`dispatchPolicy ${JSON.stringify(dispatchPolicy)} is not intent-explicit or strict-mutual-exclusion: absence is intent-explicit, never undefined`,
				);
			},
		},
		{
			name: "bindConfidentialClientRefreshTokens is true or false",
			run: async () => {
				const { bindConfidentialClientRefreshTokens } = build();
				assert.ok(
					typeof bindConfidentialClientRefreshTokens === "boolean",
					`bindConfidentialClientRefreshTokens ${JSON.stringify(bindConfidentialClientRefreshTokens)} is not a boolean: absence is false, never undefined`,
				);
			},
		},
		{
			name: "the settings are frozen",
			run: async () => {
				const found = unfrozenPath(build(), "the settings");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the settings could change them under the others`,
				);
			},
		},
	];
}
