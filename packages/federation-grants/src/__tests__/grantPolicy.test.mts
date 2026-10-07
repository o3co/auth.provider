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
 * The `federationGrantPolicy` slot as `federationGrantsModule` provides it:
 * from its own parsed section, held to core's contract, the keep policy read
 * exactly as core's `resolveFederationGrantKeepPolicy` reads it. The module
 * provides it only while it is on, so what it provides always says grants are
 * on. What a composition holds is pinned at boot, in `boot.test.mts`.
 */

import {
	checkFederationGrantPolicy,
	type FederationGrantPolicy,
	resolveFederationGrantKeepPolicy,
} from "@o3co/auth-provider-core";
import {
	type FederationGrantPolicyContractInput,
	federationGrantPolicyContract,
} from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import {
	type FederationGrantsModuleDeps,
	federationGrantsConfigSchema,
	federationGrantsModule,
} from "#/module.mjs";

/** The section as boot hands it to the module: parsed by the module's schema. */
const parsed = (section: Record<string, unknown>) => federationGrantsConfigSchema.parse(section);

/** What the module provides for `section`, with nothing else in its deps. */
const provided = (section: Record<string, unknown>): FederationGrantPolicy => {
	const provides = federationGrantsModule.provides as
		| Record<string, ((deps: FederationGrantsModuleDeps) => unknown) | undefined>
		| undefined;
	const provider = provides?.federationGrantPolicy;
	if (provider === undefined)
		throw new Error("federationGrantsModule provides no federationGrantPolicy");
	return provider({
		section: parsed(section),
	} as FederationGrantsModuleDeps) as FederationGrantPolicy;
};

/** The names of the contract cases `build` fails. */
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

describe("federationGrantsModule's federationGrantPolicy", () => {
	it("is the module's own slot: provided, named authoritative, and provided eagerly", () => {
		expect(Object.keys(federationGrantsModule.provides ?? {})).toEqual(["federationGrantPolicy"]);
		expect(federationGrantsModule.authoritative).toEqual(["federationGrantPolicy"]);
		expect(federationGrantsModule.lifecycle?.federationGrantPolicy).toEqual({ eager: true });
	});

	describe.each([
		["the switch alone", { enabled: true }],
		["a keep allowance", { enabled: true, allowKeepOnSubjectRevocation: true }],
		[
			"the spellings a variable arrives in",
			{ enabled: "1", allowKeepOnSubjectRevocation: " TRUE " },
		],
	] as const)("keeps core's contract over %s", (_what, section) => {
		it.each(federationGrantPolicyContract({ build: () => provided(section) }))(
			"$name",
			async ({ run }) => {
				await run();
			},
		);
	});

	it("is a value a reader's check answers unchanged", () => {
		for (const allowKeepOnSubjectRevocation of [true, false]) {
			const policy = provided({ enabled: true, allowKeepOnSubjectRevocation });
			expect(checkFederationGrantPolicy(policy)).toStrictEqual(policy);
		}
	});

	it("says grants are on: the module provides it only while its section switches it on", () => {
		expect(provided({ enabled: true })).toStrictEqual({
			enabled: true,
			allowKeepOnSubjectRevocation: false,
		});
	});

	it("reads the keep policy as core's resolveFederationGrantKeepPolicy reads the same section", () => {
		for (const allowKeepOnSubjectRevocation of [
			undefined,
			true,
			false,
			"true",
			"1",
			" True ",
			"false",
			"0",
			"",
		]) {
			const section = {
				enabled: true,
				...(allowKeepOnSubjectRevocation === undefined ? {} : { allowKeepOnSubjectRevocation }),
			};
			expect(
				provided(section).allowKeepOnSubjectRevocation,
				JSON.stringify(allowKeepOnSubjectRevocation),
			).toBe(resolveFederationGrantKeepPolicy(parsed(section)));
		}
		expect(provided({ enabled: true }).allowKeepOnSubjectRevocation).toBe(false);
		expect(
			provided({ enabled: true, allowKeepOnSubjectRevocation: "1" }).allowKeepOnSubjectRevocation,
		).toBe(true);
	});

	it("carries no keep allowance beside a switch that is not on", () => {
		// Boot never asks a switched-off module; were it asked, the value would
		// still keep the contract rather than allow keeping grants that do not exist.
		expect(provided({ enabled: false, allowKeepOnSubjectRevocation: true })).toStrictEqual({
			enabled: false,
			allowKeepOnSubjectRevocation: false,
		});
	});
});

describe("federationGrantPolicyContract over a provider that answers nothing", () => {
	it("fails: an absent policy reads as grants off, so a provider must never answer one", async () => {
		expect(await failing(() => undefined as unknown as FederationGrantPolicy)).toEqual([
			"enabled is true or false",
			"allowKeepOnSubjectRevocation is true or false",
			"allowKeepOnSubjectRevocation is false while grants are off",
		]);
	});
});
