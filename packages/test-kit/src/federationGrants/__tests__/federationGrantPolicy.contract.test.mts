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
 * `federationGrantPolicyContract` run over core's double of the
 * `federationGrantPolicy` slot and over what core's check answers, and the
 * proof that each case is not vacuous: policies broken one way each,
 * refused by the case that names what they break.
 */

import { checkFederationGrantPolicy, type FederationGrantPolicy } from "@o3co/auth-provider-core";
import { createTestFederationGrantPolicy } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	type FederationGrantPolicyContractInput,
	federationGrantPolicyContract,
} from "#/index.mjs";

const RULES = {
	enabled: "enabled is true or false",
	keep: "allowKeepOnSubjectRevocation is true or false",
	keepWhileOff: "allowKeepOnSubjectRevocation is false while grants are off",
	frozen: "the policy is frozen",
} as const;

/** The names of the cases `build` fails. */
const failing = async (build: FederationGrantPolicyContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of federationGrantPolicyContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** A policy built from `members` as written, frozen as a provider would hand it. */
const policyOf = (members: Record<string, unknown>): FederationGrantPolicy =>
	Object.freeze({ ...members }) as unknown as FederationGrantPolicy;

describe("federationGrantPolicyContract — core's double", () => {
	const cases = federationGrantPolicyContract({ build: () => createTestFederationGrantPolicy() });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.enabled,
			RULES.keep,
			RULES.keepWhileOff,
			RULES.frozen,
		]);
	});

	for (const contractCase of cases) {
		it(contractCase.name, contractCase.run);
	}

	it("keeps them with every combination a deployment could configure", async () => {
		for (const overrides of [
			{ enabled: false },
			{ enabled: true },
			{ enabled: true, allowKeepOnSubjectRevocation: true },
			{ enabled: true, allowKeepOnSubjectRevocation: false },
		]) {
			expect(await failing(() => createTestFederationGrantPolicy(overrides))).toEqual([]);
		}
	});
});

describe("federationGrantPolicyContract — core's check", () => {
	it("keeps every case for what the check answers", async () => {
		const double = createTestFederationGrantPolicy({ enabled: true });
		expect(await failing(() => checkFederationGrantPolicy(double))).toEqual([]);
	});
});

describe("federationGrantPolicyContract — each way a value can break it", () => {
	it("a switch that is not a boolean: absent, or the string a variable carries", async () => {
		for (const enabled of [undefined, "true", 1, null]) {
			expect(
				await failing(() => policyOf({ enabled, allowKeepOnSubjectRevocation: false })),
			).toEqual([RULES.enabled]);
		}
	});

	it("a keep policy that is not a boolean", async () => {
		for (const allowKeepOnSubjectRevocation of [undefined, "false", 0]) {
			expect(
				await failing(() => policyOf({ enabled: true, allowKeepOnSubjectRevocation })),
			).toEqual([RULES.keep]);
		}
	});

	it("an allowance to keep grants while grants are off", async () => {
		expect(
			await failing(() =>
				createTestFederationGrantPolicy({ enabled: false, allowKeepOnSubjectRevocation: true }),
			),
		).toEqual([RULES.keepWhileOff]);
	});

	it("a policy that is not frozen", async () => {
		expect(
			await failing(
				() => ({ enabled: true, allowKeepOnSubjectRevocation: false }) as FederationGrantPolicy,
			),
		).toEqual([RULES.frozen]);
	});
});
