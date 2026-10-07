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
 * A module switched off by its own section (`section.isEnabled`) registers
 * nothing: no slot, contribution, route, admission action, rate-limit budget,
 * requirement on another slot, absence policy or factory run. Its section is
 * still parsed, and its old paths still refused. A module that requires a
 * slot only the disabled module would provide is refused, as when that module
 * is not installed.
 */

import express from "express";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule, type Module } from "../../modules/manifest/index.mjs";
import { coreConfigForTests, makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import { REPLICA_UNSAFE_MODULES } from "../replica-safety.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly switchFixtureSlot: string;
		readonly switchFixtureMissing: string;
	}
}

const SwitchSection = z
	.object({ enabled: z.boolean(), retries: z.number().int().optional() })
	.strict();

const bootWith = (extra: Record<string, unknown>): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

/** Every registration a module can make, each recording that its factory ran. */
const switched = (ran: string[]): Module =>
	defineModule({
		name: "switch-fixture",
		section: {
			schema: SwitchSection,
			relocatedFrom: ["legacySwitchFixture"],
			isEnabled: (section: z.output<typeof SwitchSection>) => section.enabled,
		},
		requires: ["switchFixtureMissing"],
		absencePolicies: {
			switchFixtureMissing: {
				configKey: ["switch-fixture", "missingDeclared"],
				absentValue: true,
				hint: "the fixture slot",
			},
		},
		provides: {
			switchFixtureSlot: () => {
				ran.push("provides");
				return "provided";
			},
		},
		lifecycle: { switchFixtureSlot: { eager: true } },
		replicaSafety: { unsafe: true, reason: "the fixture forks per replica" },
		overrides: {
			mfaFactors: {
				"switch-fixture-base": () => {
					ran.push("overrides");
					return null;
				},
			},
		},
		contributes: {
			auditHooks: [
				() => {
					ran.push("auditHooks");
					return { record: async () => {} };
				},
			],
			grants: {
				"urn:test:switch-fixture": () => {
					ran.push("grants");
					return { grantType: "urn:test:switch-fixture", handle: async () => ({}) } as never;
				},
			},
			admissionActions: { "acme.switch": { grade: "use" } },
			rateLimitBudgets: {
				switch_fixture: () => {
					ran.push("rateLimitBudgets");
					return null;
				},
			},
			discoveryMetadata: [
				() => {
					ran.push("discoveryMetadata");
					return { metadata: { switch_fixture_supported: true } };
				},
			],
			routes: [
				() => {
					ran.push("routes");
					const router = express.Router();
					router.get("/", (_req, res) => {
						res.status(200).end();
					});
					return { id: "switch-fixture", mountPath: "/switch-fixture", handler: router };
				},
			],
		},
	} as never);

/** The module the fixture overrides, so its override has a target when it is switched on. */
const base = defineModule({
	name: "switch-fixture-base",
	contributes: { mfaFactors: { "switch-fixture-base": () => null } },
});

describe("a module its own section switches off", () => {
	it("registers nothing and runs no factory: no slot, contribution, override, audit hook, route, admission action, budget, requirement, absence policy or replica-safety refusal", async () => {
		const ran: string[] = [];
		const handle = await createApp({
			modules: [base, switched(ran)],
			bootstrapComponents: bootWith({
				...coreConfigForTests({ deploymentMode: "multi" }),
				"switch-fixture": { enabled: false },
			}),
		});

		expect(ran).toEqual([]);
		const components = handle.components as Record<string, unknown>;
		expect(components.switchFixtureSlot).toBeUndefined();
		expect(handle.components.auditSink).toBeUndefined();
		expect(handle.components.grantHandlerResolver?.get("urn:test:switch-fixture")).toBeUndefined();
		expect(handle.components.sessionRequirementResolver?.action("acme.switch")).toBeUndefined();
		expect(handle.routes.map((route) => route.contributedBy)).not.toContain("switch-fixture");
		await handle.dispose();
	});

	it("is checked as written when its section switches it on", async () => {
		// The unfilled requirement is what refuses it: the switch is the only difference.
		const err = await refusal(
			createApp({
				modules: [switched([])],
				bootstrapComponents: bootWith({ "switch-fixture": { enabled: true } }),
			}),
		);
		expect(err.message).toMatch(/switchFixtureMissing/);
	});

	it("still has its section parsed: a value its schema refuses refuses boot, naming the path", async () => {
		const err = await refusal(
			createApp({
				modules: [switched([])],
				bootstrapComponents: bootWith({ "switch-fixture": { enabled: false, retries: "many" } }),
			}),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/switch-fixture\.retries/);
	});

	it("still refuses a setting written at a path its section moved from", async () => {
		const err = await refusal(
			createApp({
				modules: [switched([])],
				bootstrapComponents: bootWith({
					"switch-fixture": { enabled: false },
					legacySwitchFixture: { enabled: true },
				}),
			}),
		);
		expect(err.reason).toBe("config-path-relocated");
	});

	it("leaves a module that requires its slot refused, as when it is not installed", async () => {
		const reader = defineModule({
			name: "switch-fixture-reader",
			requires: ["switchFixtureSlot"] as const,
		});
		const err = await refusal(
			createApp({
				modules: [switched([]), reader],
				bootstrapComponents: bootWith({ "switch-fixture": { enabled: false } }),
			}),
		);
		expect(err.message).toMatch(/switchFixtureSlot/);
		expect(err.message).toMatch(/switch-fixture-reader/);
	});

	it("is not refused as a replica-unsafe bundled module by its name alone", async () => {
		const [bundled] = REPLICA_UNSAFE_MODULES;
		const named = defineModule({
			name: bundled as string,
			section: { schema: SwitchSection, isEnabled: (section) => section.enabled },
		});
		const handle = await createApp({
			modules: [named],
			bootstrapComponents: bootWith({
				...coreConfigForTests({ deploymentMode: "multi" }),
				[bundled as string]: { enabled: false },
			}),
		});
		await handle.dispose();
	});

	it("frees what it would claim: another module may contribute the same name", async () => {
		const other = defineModule({
			name: "switch-fixture-other",
			contributes: { admissionActions: { "acme.switch": { grade: "use" } } },
		});
		const handle = await createApp({
			modules: [switched([]), other],
			bootstrapComponents: bootWith({ "switch-fixture": { enabled: false } }),
		});
		expect(handle.components.sessionRequirementResolver?.action("acme.switch")?.grade).toBe("use");
		await handle.dispose();
	});

	it("refuses boot, naming the section, when its switch does not answer a boolean", async () => {
		const answering = (isEnabled: (section: unknown) => unknown) =>
			defineModule({
				name: "switch-fixture-broken",
				section: { schema: SwitchSection, isEnabled },
			} as never);
		for (const isEnabled of [
			() => "yes",
			() => {
				throw new Error("switch unreadable");
			},
		]) {
			const err = await refusal(
				createApp({
					modules: [answering(isEnabled)],
					bootstrapComponents: bootWith({ "switch-fixture-broken": { enabled: false } }),
				}),
			);
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toMatch(/switch-fixture-broken/);
		}
	});
});
