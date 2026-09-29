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
 * A relocated configuration path refuses boot (#728 B10). A loaded module's
 * `section.relocatedFrom` names the paths its section moved from; a
 * configuration that still sets one refuses boot with
 * `config-path-relocated`, naming each key it sets there, the path it moved
 * to and the environment variable that binds it. Rows are the manifests'. A
 * composition that does not load the module is unaffected.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

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

const RetrySection = z.object({
	retries: z.coerce.number().int().positive(),
	label: z.string().optional(),
});

/** The fixture's section now, which every configuration below writes. */
const current = { "fixture-relocating": { retries: 3 } };

describe("a relocated path — refused", () => {
	it("a leaf key moved into the section: names the old path, the new one and its variable", async () => {
		let ran = false;
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: { "legacy.retries": "retries" } },
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
				modules: [relocating],
				bootstrapComponents: bootWith({ ...current, legacy: { retries: 3 } }),
			}),
		);

		expect(err.reason).toBe("config-path-relocated");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "fixture-relocating",
					from: "legacy.retries",
					to: "fixture-relocating.retries",
					environmentVariable: "FIXTURE_RELOCATING_RETRIES",
				},
			],
		});
		expect(err.message).toContain(
			"legacy.retries has moved to fixture-relocating.retries; see CHANGELOG.",
		);
		expect(err.message).toContain("FIXTURE_RELOCATING_RETRIES");
		expect(ran).toBe(false);
	});

	it("a whole subtree moved as the section: every key set there, each at its place in the section", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: ["legacy.fixture"] },
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({
					...current,
					legacy: { fixture: { retries: 3, label: "old" } },
				}),
			}),
		);

		expect(err.reason).toBe("config-path-relocated");
		expect(err.details).toMatchObject({
			relocated: [
				{
					module: "fixture-relocating",
					from: "legacy.fixture.retries",
					to: "fixture-relocating.retries",
					environmentVariable: "FIXTURE_RELOCATING_RETRIES",
				},
				{
					module: "fixture-relocating",
					from: "legacy.fixture.label",
					to: "fixture-relocating.label",
					environmentVariable: "FIXTURE_RELOCATING_LABEL",
				},
			],
		});
	});

	it("a subtree whose keys were renamed as it moved: each key at its new name", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				relocatedFrom: {
					"legacy.fixture": "",
					"legacy.fixture.max-retries": "retries",
				},
			},
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({
					...current,
					legacy: { fixture: { "max-retries": 3, label: "old" } },
				}),
			}),
		);

		expect(err.details).toMatchObject({
			relocated: [
				{ from: "legacy.fixture.max-retries", to: "fixture-relocating.retries" },
				{ from: "legacy.fixture.label", to: "fixture-relocating.label" },
			],
		});
	});

	it("moves into the section where it sits today, when that is still a transitional path", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				at: "legacy.current",
				relocatedFrom: { "legacy.current.max-retries": "retries" },
			},
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ legacy: { current: { retries: 3, "max-retries": 3 } } }),
			}),
		);

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "fixture-relocating",
					from: "legacy.current.max-retries",
					to: "legacy.current.retries",
					environmentVariable: "LEGACY_CURRENT_RETRIES",
				},
			],
		});
	});

	it("is refused before the configuration is parsed: the old path is named, not what a schema makes of it", async () => {
		// Without the relocation, the module's own configSchema would refuse
		// `legacy.retries` as not a number (config-validation-failed).
		const relocating = defineModule({
			name: "fixture-relocating",
			configSchema: z.object({ legacy: z.object({ retries: z.number() }).optional() }),
			section: { schema: RetrySection, relocatedFrom: { "legacy.retries": "retries" } },
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ ...current, legacy: { retries: "three" } }),
			}),
		);

		expect(err.reason).toBe("config-path-relocated");
	});
});

describe("a relocated path — not refused", () => {
	it("a composition that does not load the relocating module boots with the old path set", async () => {
		const unrelated = defineModule({
			name: "fixture-unrelated",
			section: { schema: RetrySection },
		});

		const handle = await createApp({
			modules: [unrelated],
			bootstrapComponents: bootWith({
				"fixture-unrelated": { retries: 1 },
				legacy: { retries: 3, fixture: { retries: 3 } },
			}),
		});

		await handle.dispose();
	});

	it("a configuration that sets nothing at the old path boots with the module loaded", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				relocatedFrom: ["legacy.fixture", "legacy.retries"],
			},
		});

		const handle = await createApp({
			modules: [relocating],
			bootstrapComponents: bootWith({ ...current, legacy: { unrelated: 1 } }),
		});

		await handle.dispose();
	});
});

describe("a relocated path — a manifest that names one it cannot", () => {
	it.each([
		["an empty old path", [""], ""],
		["an old path with an empty key", ["legacy..fixture"], "legacy..fixture"],
		["a new path with an empty key", { "legacy.retries": "a..b" }, "legacy.retries"],
		["a new path that is not a string", { "legacy.retries": 1 }, "legacy.retries"],
		["its own section's path", ["fixture-relocating"], "fixture-relocating"],
		["neither a list nor a map", "legacy.fixture", "legacy.fixture"],
	])("refuses %s at stage 1", async (_label, relocatedFrom, named) => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: relocatedFrom as never },
		});

		const err = await refusal(
			createApp({ modules: [relocating], bootstrapComponents: bootWith(current) }),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			reason: "module-section-path-invalid",
			module: "fixture-relocating",
			relocatedFrom: named,
			problem: expect.any(String),
		});
	});

	it("refuses an old path that holds a loaded module's section: the section itself would be refused", async () => {
		const other = defineModule({
			name: "fixture-other",
			section: { schema: RetrySection, at: "legacy.other" },
		});
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: ["legacy"] },
		});

		const err = await refusal(
			createApp({
				modules: [other, relocating],
				bootstrapComponents: bootWith({ ...current, legacy: { other: { retries: 1 } } }),
			}),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-relocating",
			relocatedFrom: "legacy",
			problem: expect.stringContaining("fixture-other"),
		});
	});
});

describe("a relocated path — claimed by two loaded modules", () => {
	const relocating = (name: string, relocatedFrom: readonly string[] | Record<string, string>) =>
		defineModule({ name, section: { schema: RetrySection, relocatedFrom } });

	it.each([
		["the same old path", ["legacy.fixture"], ["legacy.fixture"]],
		["an old path covering the other's", ["legacy"], { "legacy.fixture.retries": "retries" }],
		["an old path under the other's", { "legacy.fixture.retries": "retries" }, ["legacy"]],
	] as const)(
		"refuses %s at stage 1, naming both modules: which one a key moved to would be a guess",
		async (_label, first, second) => {
			const err = await refusal(
				createApp({
					modules: [relocating("fixture-first", first), relocating("fixture-second", second)],
					bootstrapComponents: bootWith({
						"fixture-first": { retries: 1 },
						"fixture-second": { retries: 1 },
					}),
				}),
			);

			expect(err.reason).toBe("module-section-path-invalid");
			expect(err.stage).toBe("validateManifests");
			expect(err.details).toMatchObject({
				reason: "module-section-path-invalid",
				module: "fixture-second",
				relocatedFrom: Array.isArray(second) ? second[0] : Object.keys(second)[0],
			});
			const problem = (err.details as { problem?: string }).problem ?? "";
			expect(problem).toContain('"fixture-first"');
			expect(problem).toContain('"fixture-second"');
		},
	);

	it("lets one module cover its own old path with a more specific one: a subtree and a key renamed in it", async () => {
		const handle = await createApp({
			modules: [
				relocating("fixture-relocating", {
					"legacy.fixture": "",
					"legacy.fixture.max-retries": "retries",
				}),
			],
			bootstrapComponents: bootWith(current),
		});
		await handle.dispose();
	});
});
