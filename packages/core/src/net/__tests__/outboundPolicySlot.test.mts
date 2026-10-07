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
 * The `outboundPolicy` slot: the destination policy `core.outbound` states,
 * as core's one reader of the section (`outboundPolicyOf`) answers it. Core
 * fills it from the configuration before any provider runs, for every
 * composition, and reserves the key, so a module builds its outbound fetch
 * from its dependencies rather than from `config`. Its contract suite, run
 * over what core fills, and its test double.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { BootstrapMap } from "#/boot/types.mjs";
import { createApp, defineModule, type OutboundPolicy, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { outboundPolicyOf } from "#/net/outbound-fetch.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestOutboundPolicy, type OutboundSectionForTests } from "#/testing/index.mjs";
import { outboundPolicyContract } from "./outboundPolicy.contract.mjs";

const RULES = [
	"allowedHosts, deniedHosts and internalHosts are lists of host patterns",
	"timeoutMs is a whole number from 1 to 2147483647",
	"maxResponseBytes is a positive whole number",
	"egress is direct or absent",
	"the policy is frozen",
];

/** The names of the cases `policy` fails. */
const failing = async (policy: unknown): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of outboundPolicyContract({ build: () => policy as OutboundPolicy })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** A policy as the reader states one, every member frozen, with `members` replaced. */
const frozenPolicy = (members: Record<string, unknown> = {}): unknown =>
	Object.freeze({
		allowedHosts: Object.freeze([Object.freeze({ host: "rp.example", suffix: false })]),
		deniedHosts: Object.freeze([]),
		internalHosts: Object.freeze([Object.freeze({ host: "internal.example", suffix: true })]),
		timeoutMs: 5000,
		maxResponseBytes: 65536,
		egress: undefined,
		...members,
	});

describe("the outboundPolicy slot", () => {
	it("is optional, and holds the outbound destination policy", () => {
		expectTypeOf<ComponentMap["outboundPolicy"]>().toEqualTypeOf<OutboundPolicy | undefined>();
		expectTypeOf<
			ProviderDeps<"outboundPolicy">["outboundPolicy"]
		>().toEqualTypeOf<OutboundPolicy>();
		expect(true).toBe(true);
	});
});

describe("outboundPolicyContract", () => {
	it("names its rules", () => {
		expect(
			outboundPolicyContract({ build: () => createTestOutboundPolicy() }).map((c) => c.name),
		).toEqual(RULES);
	});

	it("keeps them for a policy as the reader states one", async () => {
		expect(await failing(frozenPolicy())).toEqual([]);
		expect(await failing(frozenPolicy({ egress: "direct", timeoutMs: 2_147_483_647 }))).toEqual([]);
	});

	it("fails the first for a host list that is not a list of host patterns", async () => {
		for (const allowedHosts of [
			undefined,
			"rp.example",
			Object.freeze(["rp.example"]),
			Object.freeze([Object.freeze({ host: "", suffix: false })]),
			Object.freeze([Object.freeze({ host: "rp.example", suffix: "no" })]),
		]) {
			expect(await failing(frozenPolicy({ allowedHosts }))).toEqual([RULES[0]]);
		}
	});

	it("fails the second for a deadline the fetch could not hold", async () => {
		for (const timeoutMs of [0, -1, 1.5, 2_147_483_648, "5000", undefined]) {
			expect(await failing(frozenPolicy({ timeoutMs }))).toEqual([RULES[1]]);
		}
	});

	it("fails the third for a cap that is not a positive whole number", async () => {
		for (const maxResponseBytes of [0, -1, 1.5, Number.POSITIVE_INFINITY, "65536", undefined]) {
			expect(await failing(frozenPolicy({ maxResponseBytes }))).toEqual([RULES[2]]);
		}
	});

	it("fails the fourth for any egress but direct", async () => {
		for (const egress of ["proxy", "Direct", "", null]) {
			expect(await failing(frozenPolicy({ egress }))).toEqual([RULES[3]]);
		}
	});

	it("fails the fifth for a policy a reader could change, a host pattern included", async () => {
		expect(await failing({ ...(frozenPolicy() as Record<string, unknown>) })).toEqual([RULES[4]]);
		expect(
			await failing(
				frozenPolicy({ deniedHosts: Object.freeze([{ host: "bad.example", suffix: false }]) }),
			),
		).toEqual([RULES[4]]);
	});
});

describe("createTestOutboundPolicy", () => {
	it("answers what an unset core.outbound reads as, keeping the contract", async () => {
		const policy = createTestOutboundPolicy();
		expect(policy).toEqual(outboundPolicyOf({}));
		expect(await failing(policy)).toEqual([]);
	});

	it("reads the section a test writes, as core's reader does", async () => {
		const section: OutboundSectionForTests = {
			allowedHosts: [".partner.example"],
			internalHosts: "localhost",
			timeoutMs: 1000,
			egress: "direct",
		};
		const policy = createTestOutboundPolicy(section);
		expect(policy).toEqual(outboundPolicyOf({ core: { outbound: section } }));
		expect(await failing(policy)).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Core fills it
// ---------------------------------------------------------------------------

/** `core.outbound` sections core's schema accepts. */
const ACCEPTED: readonly (readonly [string, OutboundSectionForTests | undefined])[] = [
	["no outbound section", undefined],
	["an empty section", {}],
	[
		"every key",
		{
			allowedHosts: ["rp.example", ".partner.example"],
			deniedHosts: "bad.example, .worse.example",
			internalHosts: ["localhost", "10.0.0.7"],
			timeoutMs: "2000",
			maxResponseBytes: 1024,
			egress: "direct",
		},
	],
];

/** A valid core configuration with `core.outbound` as given, and whatever else `extra` holds. */
const bootstrap = (
	outbound: OutboundSectionForTests | undefined,
	extra: Record<string, unknown> = {},
): BootstrapMap => {
	const base = makeValidCoreConfig();
	return {
		config: outbound === undefined ? base : { ...base, core: { ...base.core, outbound } },
		pathResolver: (s: string) => s,
		...extra,
	} as unknown as BootstrapMap;
};

/** A module whose route factory records the policy it was handed, and nothing of `config`. */
const readerModule = (seen: unknown[]) =>
	defineModule({
		name: "test:outbound-policy-reader",
		requires: ["outboundPolicy"] as const,
		contributes: {
			routes: [
				(deps) => {
					seen.push(deps.outboundPolicy);
					return {
						id: "test-outbound-policy-reader",
						mountPath: "/__test-outbound-policy-reader__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});

describe("core fills outboundPolicy from the configuration's core.outbound", () => {
	it("fills the defaults when core.outbound is absent", async () => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(undefined) });
		try {
			expect(handle.components.outboundPolicy).toEqual({
				allowedHosts: [],
				deniedHosts: [],
				internalHosts: [],
				timeoutMs: 5000,
				maxResponseBytes: 65536,
				egress: undefined,
			});
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)(
		"fills it with what %s states: the reader's answer over the configuration",
		async (_what, outbound) => {
			const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(outbound) });
			try {
				expect(handle.components.outboundPolicy).toEqual(
					outboundPolicyOf(handle.components.config),
				);
			} finally {
				await handle.dispose();
			}
		},
	);

	it("reads every key the section states", async () => {
		const handle = await createApp({
			modules: [],
			bootstrapComponents: bootstrap(ACCEPTED[2]?.[1]),
		});
		try {
			expect(handle.components.outboundPolicy).toEqual({
				allowedHosts: [
					{ host: "rp.example", suffix: false },
					{ host: "partner.example", suffix: true },
				],
				deniedHosts: [
					{ host: "bad.example", suffix: false },
					{ host: "worse.example", suffix: true },
				],
				internalHosts: [
					{ host: "localhost", suffix: false },
					{ host: "10.0.0.7", suffix: false },
				],
				timeoutMs: 2000,
				maxResponseBytes: 1024,
				egress: "direct",
			});
		} finally {
			await handle.dispose();
		}
	});

	it.each(ACCEPTED)("keeps the slot's contract, deeply frozen, for %s", async (_what, outbound) => {
		const handle = await createApp({ modules: [], bootstrapComponents: bootstrap(outbound) });
		try {
			const filled = handle.components.outboundPolicy;
			for (const { name, run } of outboundPolicyContract({
				build: () => filled as OutboundPolicy,
			})) {
				await expect(run(), name).resolves.toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});

	it("hands a module that requires it the policy the world keeps", async () => {
		const seen: unknown[] = [];
		const handle = await createApp({
			modules: [readerModule(seen)],
			bootstrapComponents: bootstrap({ allowedHosts: ["rp.example"] }),
		});
		try {
			expect(seen).toHaveLength(1);
			expect(seen[0]).toBe(handle.components.outboundPolicy);
		} finally {
			await handle.dispose();
		}
	});
});

// ---------------------------------------------------------------------------
// The key is reserved
// ---------------------------------------------------------------------------

describe("the outboundPolicy key is reserved", () => {
	const policy = createTestOutboundPolicy({ allowedHosts: ["rp.example"] });
	const provider = defineModule({
		name: "test:provides-outbound-policy",
		provides: { outboundPolicy: () => policy },
	});
	const REMEDY =
		"Set core.outbound in the configuration instead: boot fills outboundPolicy from it.";

	it("refuses a module that provides it, naming the module", async () => {
		await expect(
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "outboundPolicy",
				source: "module-provides",
				module: "test:provides-outbound-policy",
			},
		});
	});

	it("refuses bootstrapComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { outboundPolicy: policy }),
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "outboundPolicy",
				source: "bootstrapComponents",
			},
		});
	});

	it("refuses overrideComponents that set it", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { outboundPolicy: policy },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "synthetic-key-collision",
			details: {
				reason: "synthetic-key-collision",
				componentKey: "outboundPolicy",
				source: "overrideComponents",
			},
		});
	});

	it("tells whoever set it to set core.outbound instead, from every source", async () => {
		for (const boot of [
			createApp({ modules: [provider], bootstrapComponents: bootstrap(undefined) }),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined, { outboundPolicy: policy }),
			}),
			createApp({
				modules: [],
				bootstrapComponents: bootstrap(undefined),
				overrideComponents: { outboundPolicy: policy },
			}),
		]) {
			const err = (await boot.catch((thrown: unknown) => thrown)) as Error;
			expect(err.message).toContain(REMEDY);
		}
	});
});
