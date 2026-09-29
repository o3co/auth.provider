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
 * A module's own configuration section, delivered by boot (#728): the
 * manifest's `section.schema` parses the value at `section.at` (the module's
 * name when unset) out of the configuration boot already has, and every
 * factory of the module — `provides`, name-keyed and list-shaped
 * `contributes`, `overrides` — receives the parsed value as `deps.section`.
 * A value the schema refuses refuses boot, naming the path the operator
 * wrote. A module that declares no section is booted exactly as before.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly sectionFixtureSlot: number;
	}
}

/** Coerces, so a delivered `3` proves the section was parsed, not handed over raw. */
const RetrySection = z.object({
	retries: z.coerce.number().int().positive(),
	label: z.string().optional(),
});

const bootWith = (extra: Record<string, unknown>): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

describe("a module's section — delivered as deps.section", () => {
	it("every factory of the module receives its section, parsed by its schema", async () => {
		const seen: Record<string, unknown> = {};
		// A module the sectioned one overrides, so the override position runs too.
		const base = defineModule({
			name: "section-base",
			contributes: { mfaFactors: { "fixture-factor": () => null } },
		});
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			provides: {
				sectionFixtureSlot: (deps) => {
					seen.provides = deps.section;
					return deps.section.retries;
				},
			},
			lifecycle: { sectionFixtureSlot: { eager: true } },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen.listShaped = deps.section;
						return null;
					},
				],
				mfaFactors: {
					"fixture-own-factor": (deps) => {
						seen.nameKeyed = deps.section;
						return null;
					},
				},
			},
			overrides: {
				mfaFactors: {
					"fixture-factor": (deps) => {
						seen.overrides = deps.section;
						return null;
					},
				},
			},
		});

		const handle = await createApp({
			modules: [base, sectioned],
			bootstrapComponents: bootWith({ "fixture-section": { retries: "3" } }),
		});

		const parsed = { retries: 3 };
		expect(seen).toEqual({
			provides: parsed,
			listShaped: parsed,
			nameKeyed: parsed,
			overrides: parsed,
		});
		expect(handle.components.sectionFixtureSlot).toBe(3);
		await handle.dispose();
	});

	it("reads the section at `at` when the manifest names a transitional path", async () => {
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection, at: "legacy.fixture" },
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				legacy: { fixture: { retries: "5", label: "old home" } },
				// The module's name is not where this section is read from.
				"fixture-section": { retries: "not read" },
			}),
		});

		expect(seen).toEqual({ retries: 5, label: "old home" });
		await handle.dispose();
	});

	it("leaves the config slot as it was: the section is handed over beside it", async () => {
		let config: unknown;
		let section: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			requires: ["config"],
			section: { schema: RetrySection },
			contributes: {
				grantMiddleware: [
					(deps) => {
						config = deps.config;
						section = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({ "fixture-section": { retries: "3" } }),
		});

		expect(section).toEqual({ retries: 3 });
		expect((config as Record<string, unknown>)["fixture-section"]).toEqual({ retries: "3" });
		await handle.dispose();
	});

	it("declares reference and relocatedFrom without acting on them: nothing is read or refused", async () => {
		let seen: unknown;
		const sectioned = defineModule({
			name: "fixture-section",
			section: {
				schema: RetrySection,
				reference: new URL("file:///nonexistent/config/reference.conf"),
				relocatedFrom: ["legacy.fixture"],
			},
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.section;
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [sectioned],
			bootstrapComponents: bootWith({
				"fixture-section": { retries: "2" },
				legacy: { fixture: { retries: "9" } },
			}),
		});

		expect(seen).toEqual({ retries: 2 });
		await handle.dispose();
	});
});

describe("a module's section — a value its schema refuses refuses boot", () => {
	it("names the operator's path, and no factory runs", async () => {
		let ran = false;
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
			contributes: {
				grantMiddleware: [
					() => {
						ran = true;
						return null;
					},
				],
			},
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ "fixture-section": { retries: "many" } }),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.stage).toBe("validateManifests");
		expect(err.message).toContain("fixture-section.retries");
		expect(err.details).toMatchObject({
			reason: "config-validation-failed",
			issues: [expect.objectContaining({ path: ["fixture-section", "retries"] })],
			modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
		});
		expect(ran).toBe(false);
	});

	it("names the transitional path when the section is read at `at`", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection, at: "legacy.fixture" },
		});

		const err = await refusal(
			createApp({
				modules: [sectioned],
				bootstrapComponents: bootWith({ legacy: { fixture: { retries: -1 } } }),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("legacy.fixture.retries");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["legacy", "fixture", "retries"] })],
			modules: [{ module: "fixture-section", schemaPath: "legacy.fixture" }],
		});
	});

	it("refuses a missing section its schema requires, naming the section", async () => {
		const sectioned = defineModule({
			name: "fixture-section",
			section: { schema: RetrySection },
		});

		const err = await refusal(
			createApp({ modules: [sectioned], bootstrapComponents: bootWith({}) }),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("fixture-section");
		expect(err.details).toMatchObject({
			issues: [expect.objectContaining({ path: ["fixture-section"] })],
			modules: [{ module: "fixture-section", schemaPath: "fixture-section" }],
		});
	});

	it("reports every refused section at once, in module order", async () => {
		const first = defineModule({ name: "fixture-first", section: { schema: RetrySection } });
		const fine = defineModule({ name: "fixture-fine", section: { schema: RetrySection } });
		const second = defineModule({ name: "fixture-second", section: { schema: RetrySection } });

		const err = await refusal(
			createApp({
				modules: [first, fine, second],
				bootstrapComponents: bootWith({
					"fixture-first": { retries: 0 },
					"fixture-fine": { retries: 1 },
					"fixture-second": { retries: "x" },
				}),
			}),
		);

		expect(err.message).toContain("fixture-first.retries");
		expect(err.message).toContain("fixture-second.retries");
		expect(err.details).toMatchObject({
			issues: [
				expect.objectContaining({ path: ["fixture-first", "retries"] }),
				expect.objectContaining({ path: ["fixture-second", "retries"] }),
			],
			modules: [
				{ module: "fixture-first", schemaPath: "fixture-first" },
				{ module: "fixture-second", schemaPath: "fixture-second" },
			],
		});
	});
});

describe("a module without a section", () => {
	it("is booted as before: its deps carry no section key", async () => {
		let keys: readonly string[] | undefined;
		const plain = defineModule({
			name: "fixture-plain",
			requires: ["config"],
			contributes: {
				grantMiddleware: [
					(deps) => {
						keys = Object.keys(deps);
						return null;
					},
				],
			},
		});

		const handle = await createApp({
			modules: [plain],
			// A value at the module's name is not a section it declared: nothing parses it.
			bootstrapComponents: bootWith({ "fixture-plain": { retries: "not a number" } }),
		});

		expect(keys).toEqual(["config"]);
		await handle.dispose();
	});
});
