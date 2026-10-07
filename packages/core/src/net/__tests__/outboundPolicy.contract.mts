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
 * The contract suite of the `outboundPolicy` slot, which core alone fills.
 * `outboundPolicyContract(input)` holds the policy to what core's reader of
 * `core.outbound` answers: three lists of host patterns, a deadline a timer
 * can hold, a positive body cap, an egress that is `"direct"` or absent, the
 * whole frozen.
 */

import assert from "node:assert/strict";
import { MAX_TIMEOUT_MS, type OutboundPolicy } from "#/net/outbound-policy.mjs";
import type { ContractCase } from "#/session-admission/testing/requirement.contract.mjs";
import { unfrozenPath } from "#/testing/slots/shared.mjs";

export interface OutboundPolicyContractInput {
	/** The policy under test: what core fills the slot with, from the configuration its test chose. */
	readonly build: () => OutboundPolicy;
}

const LISTS = ["allowedHosts", "deniedHosts", "internalHosts"] as const;

/** Whether `value` is a list of host patterns: each a non-empty host and a boolean suffix. */
const isPatternList = (value: unknown): boolean =>
	Array.isArray(value) &&
	value.every(
		(pattern: unknown) =>
			typeof pattern === "object" &&
			pattern !== null &&
			typeof (pattern as { host?: unknown }).host === "string" &&
			(pattern as { host: string }).host.length > 0 &&
			typeof (pattern as { suffix?: unknown }).suffix === "boolean",
	);

/** The cases of the `outboundPolicy` contract over the policy `input` builds. */
export function outboundPolicyContract(
	input: OutboundPolicyContractInput,
): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "allowedHosts, deniedHosts and internalHosts are lists of host patterns",
			run: async () => {
				const policy = build();
				for (const list of LISTS) {
					assert.ok(
						isPatternList(policy[list]),
						`${list} is not a list of { host, suffix } patterns: an empty list is [], never undefined`,
					);
				}
			},
		},
		{
			name: `timeoutMs is a whole number from 1 to ${MAX_TIMEOUT_MS}`,
			run: async () => {
				const { timeoutMs } = build();
				assert.ok(
					Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= MAX_TIMEOUT_MS,
					`timeoutMs ${JSON.stringify(timeoutMs)} is not a whole number from 1 to ${MAX_TIMEOUT_MS}: absence is the default, never undefined`,
				);
			},
		},
		{
			name: "maxResponseBytes is a positive whole number",
			run: async () => {
				const { maxResponseBytes } = build();
				assert.ok(
					Number.isSafeInteger(maxResponseBytes) && maxResponseBytes >= 1,
					`maxResponseBytes ${JSON.stringify(maxResponseBytes)} is not a positive whole number: absence is the default, never undefined`,
				);
			},
		},
		{
			name: "egress is direct or absent",
			run: async () => {
				const { egress } = build();
				assert.ok(
					egress === undefined || egress === "direct",
					`egress ${JSON.stringify(egress)} is neither "direct" nor undefined`,
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
