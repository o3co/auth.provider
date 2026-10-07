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
 * The `federationGrantPolicy` slot: what modules outside the federation-grants
 * module read of its section — whether grants are on, and whether a
 * subject-wide revocation may leave them standing — its check and the test
 * double. A composition that holds no slot has grants off. The slot's contract
 * suite is the test kit's, and runs over this double and the check there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import {
	checkFederationGrantPolicy,
	type FederationGrantPolicy,
} from "#/federation-grants/policy.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestFederationGrantPolicy } from "#/testing/index.mjs";

/** Boots `modules` beside a reader of the slot, and answers what the reader was handed. */
const readThroughBoot = async (
	modules: readonly ReturnType<typeof defineModule>[],
): Promise<FederationGrantPolicy | undefined> => {
	let seen: FederationGrantPolicy | undefined;
	let read = false;
	const reader = defineModule({
		name: "test:federation-grant-policy-reader",
		optional: ["federationGrantPolicy"] as const,
		contributes: {
			routes: [
				(deps) => {
					read = true;
					seen = deps.federationGrantPolicy;
					return {
						id: "test-federation-grant-policy-reader",
						mountPath: "/__test_federation_grant_policy_reader__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});
	const handle = await createApp({
		modules: [...modules, reader],
		bootstrapComponents: {
			config: makeValidCoreConfig(),
			pathResolver: (p: string) => p,
		} as never,
	});
	try {
		expect(read).toBe(true);
		return seen;
	} finally {
		await handle.dispose();
	}
};

describe("the federationGrantPolicy slot", () => {
	it("is optional, and holds the switch and the keep policy", () => {
		expectTypeOf<ComponentMap["federationGrantPolicy"]>().toEqualTypeOf<
			FederationGrantPolicy | undefined
		>();
		expectTypeOf<
			ProviderDeps<never, "federationGrantPolicy">["federationGrantPolicy"]
		>().toEqualTypeOf<FederationGrantPolicy | undefined>();
		expectTypeOf<FederationGrantPolicy["enabled"]>().toEqualTypeOf<boolean>();
		expectTypeOf<FederationGrantPolicy["allowKeepOnSubjectRevocation"]>().toEqualTypeOf<boolean>();
		// The two members are all the double answers, as the check carries.
		expect(Object.keys(createTestFederationGrantPolicy()).sort()).toEqual([
			"allowKeepOnSubjectRevocation",
			"enabled",
		]);
	});

	it("is filled by a module, and read by another", async () => {
		const policy = createTestFederationGrantPolicy({
			enabled: true,
			allowKeepOnSubjectRevocation: true,
		});
		const owner = defineModule({
			name: "test:federation-grant-policy-owner",
			provides: { federationGrantPolicy: () => policy },
		});
		expect(await readThroughBoot([owner])).toEqual(policy);
	});

	it("is absent from a composition no module fills it in: its readers have grants off", async () => {
		const seen = await readThroughBoot([]);
		expect(seen).toBeUndefined();
	});
});

describe("createTestFederationGrantPolicy", () => {
	it("answers grants off, nothing kept, frozen", () => {
		const policy = createTestFederationGrantPolicy();
		expect(policy).toStrictEqual({ enabled: false, allowKeepOnSubjectRevocation: false });
		expect(Object.isFrozen(policy)).toBe(true);
	});

	it("applies an override", () => {
		expect(
			createTestFederationGrantPolicy({ enabled: true, allowKeepOnSubjectRevocation: true }),
		).toStrictEqual({ enabled: true, allowKeepOnSubjectRevocation: true });
	});

	it("does not check what it is handed: a test of a broken value builds it here", () => {
		expect(createTestFederationGrantPolicy({ allowKeepOnSubjectRevocation: true })).toStrictEqual({
			enabled: false,
			allowKeepOnSubjectRevocation: true,
		});
	});
});

describe("checkFederationGrantPolicy", () => {
	it("answers a policy that keeps the contract as a frozen copy, whichever combination", () => {
		for (const [enabled, allowKeepOnSubjectRevocation] of [
			[false, false],
			[true, false],
			[true, true],
		] as const) {
			const value = { enabled, allowKeepOnSubjectRevocation };
			const checked = checkFederationGrantPolicy(value);
			expect(checked).toStrictEqual(value);
			expect(checked).not.toBe(value);
			expect(Object.isFrozen(checked)).toBe(true);
		}
	});

	it("carries nothing but the two members", () => {
		const checked = checkFederationGrantPolicy({
			enabled: true,
			allowKeepOnSubjectRevocation: false,
			connections: {},
		});
		expect(Object.keys(checked).sort()).toEqual(["allowKeepOnSubjectRevocation", "enabled"]);
	});

	it("reads each member once: what it checked is what it answers", () => {
		let reads = 0;
		const value = {
			get enabled() {
				reads += 1;
				return reads === 1;
			},
			allowKeepOnSubjectRevocation: true,
		};
		const checked = checkFederationGrantPolicy(value);
		expect(reads).toBe(1);
		expect(checked.enabled).toBe(true);
		expect(checked.enabled).toBe(true);
	});

	it("is not changed by a later change to the value it was handed", () => {
		const value = { enabled: true, allowKeepOnSubjectRevocation: true };
		const checked = checkFederationGrantPolicy(value);
		value.allowKeepOnSubjectRevocation = false;
		expect(checked.allowKeepOnSubjectRevocation).toBe(true);
	});

	it("refuses something that is not a policy object, naming the slot", () => {
		for (const value of [undefined, null, true, "enabled", [true, false]]) {
			expect(() => checkFederationGrantPolicy(value)).toThrow(RangeError);
			expect(() => checkFederationGrantPolicy(value)).toThrow(/^federationGrantPolicy must be/);
		}
	});

	it("refuses a member that is missing or not a boolean, naming it", () => {
		const cases: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
			["federationGrantPolicy.enabled", { allowKeepOnSubjectRevocation: false }],
			["federationGrantPolicy.enabled", { enabled: "true", allowKeepOnSubjectRevocation: false }],
			["federationGrantPolicy.allowKeepOnSubjectRevocation", { enabled: true }],
			[
				"federationGrantPolicy.allowKeepOnSubjectRevocation",
				{ enabled: true, allowKeepOnSubjectRevocation: "1" },
			],
		];
		for (const [member, value] of cases) {
			expect(() => checkFederationGrantPolicy(value)).toThrow(RangeError);
			expect(() => checkFederationGrantPolicy(value)).toThrow(new RegExp(`^${member} `));
		}
	});

	it("names what a refused member carries, and none for one that is missing", () => {
		expect(() =>
			checkFederationGrantPolicy({ enabled: "yes", allowKeepOnSubjectRevocation: false }),
		).toThrow(/the string "yes"/);
		expect(() => checkFederationGrantPolicy({ enabled: true })).toThrow(/carries none/);
	});

	it("refuses an allowance to keep grants while grants are off", () => {
		expect(() =>
			checkFederationGrantPolicy({ enabled: false, allowKeepOnSubjectRevocation: true }),
		).toThrow(/^federationGrantPolicy\.allowKeepOnSubjectRevocation must be false while/);
	});

	it("refuses a member whose read throws, naming it, with the error as its cause", () => {
		const failure = new Error("trap");
		const value = {
			enabled: true,
			get allowKeepOnSubjectRevocation(): boolean {
				throw failure;
			},
		};
		let thrown: unknown;
		try {
			checkFederationGrantPolicy(value);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(RangeError);
		expect((thrown as Error).message).toMatch(
			/^federationGrantPolicy\.allowKeepOnSubjectRevocation could not be read/,
		);
		expect((thrown as Error).cause).toBe(failure);
	});

	it("refuses the first member that is refused, and reads no member after it", () => {
		let laterRead = false;
		const value = {
			enabled: "true",
			get allowKeepOnSubjectRevocation(): boolean {
				laterRead = true;
				throw new Error("must not be read");
			},
		};
		expect(() => checkFederationGrantPolicy(value)).toThrow(
			/^federationGrantPolicy\.enabled must be true or false/,
		);
		expect(laterRead).toBe(false);
	});

	it("passes what the double answers, as a copy equal to it", () => {
		const double = createTestFederationGrantPolicy({ enabled: true });
		expect(checkFederationGrantPolicy(double)).toStrictEqual(double);
	});
});
