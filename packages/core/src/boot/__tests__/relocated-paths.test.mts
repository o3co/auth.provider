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
 * A relocated configuration path refuses boot. A loaded module's
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

	it("a value written at a path moved whole as the section: names the section, and no variable, since a section has none", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: ["legacy.fixture"] },
		});
		for (const value of [null, 5, "on"]) {
			const err = await refusal(
				createApp({
					modules: [relocating],
					bootstrapComponents: bootWith({ ...current, legacy: { fixture: value } }),
				}),
			);
			expect(err.details, String(value)).toEqual({
				reason: "config-path-relocated",
				relocated: [
					{ module: "fixture-relocating", from: "legacy.fixture", to: "fixture-relocating" },
				],
			});
			expect(err.message, String(value)).toContain(
				"legacy.fixture has moved to fixture-relocating; see CHANGELOG. Write it there and remove",
			);
			expect(err.message, String(value)).not.toContain("environment variable");
		}
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

		// The new path is under a transitional `at`: no variable binds it yet, so none is named.
		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "fixture-relocating",
					from: "legacy.current.max-retries",
					to: "legacy.current.retries",
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

	it.each([
		["a Date", () => new Date()],
		["a Map", () => new Map([["legacy.fixture", ""]])],
		[
			"a class instance",
			() =>
				new (class Relocations {
					readonly "legacy.fixture" = "";
				})(),
		],
	] as const)(
		"refuses relocatedFrom that is %s: a list or a plain map, nothing read as one",
		async (_label, make) => {
			const relocatedFrom = make();
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
				problem: expect.stringContaining("a list of old paths, or a map"),
			});
			expect((err.details as { relocatedFrom?: unknown }).relocatedFrom).toBe(relocatedFrom);
		},
	);

	it("refuses a list with a hole, naming its index, rather than throwing on it", async () => {
		const relocatedFrom: string[] = ["legacy.a"];
		relocatedFrom[2] = "legacy.b";
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom },
		});

		const err = await refusal(
			createApp({ modules: [relocating], bootstrapComponents: bootWith(current) }),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-relocating",
			problem: expect.stringContaining("index 1"),
		});
		expect((err.details as { relocatedFrom?: unknown }).relocatedFrom).toBe(relocatedFrom);
	});

	it("reads a map with no prototype as a map", async () => {
		const relocatedFrom: Record<string, string> = Object.assign(Object.create(null), {
			"legacy.retries": "retries",
		});
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom },
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ ...current, legacy: { retries: 3 } }),
			}),
		);

		expect(err.reason).toBe("config-path-relocated");
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

describe("a relocated path — more", () => {
	it("an old path left empty, as HOCON leaves an unset variable's object, sets nothing: it boots", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, relocatedFrom: ["legacy.fixture"] },
		});

		const handle = await createApp({
			modules: [relocating],
			bootstrapComponents: bootWith({ ...current, legacy: { fixture: {} } }),
		});

		await handle.dispose();
	});

	it("a key removed rather than moved — a map entry to null — is refused as removed", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				relocatedFrom: { "oauth-legacy.grants.authorization_code.pkce.requireS256": null },
			},
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({
					...current,
					"oauth-legacy": { grants: { authorization_code: { pkce: { requireS256: true } } } },
				}),
			}),
		);

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "fixture-relocating",
					from: "oauth-legacy.grants.authorization_code.pkce.requireS256",
					to: null,
				},
			],
		});
		expect(err.message).toContain(
			"oauth-legacy.grants.authorization_code.pkce.requireS256 was removed; see CHANGELOG.",
		);
	});

	it("names every key, of every module, in module order, each attributed to its module", async () => {
		const first = defineModule({
			name: "fixture-first",
			section: { schema: RetrySection, relocatedFrom: { "legacy-first.retries": "retries" } },
		});
		const second = defineModule({
			name: "fixture-second",
			section: { schema: RetrySection, relocatedFrom: ["legacy-second"] },
		});

		const err = await refusal(
			createApp({
				modules: [first, second],
				bootstrapComponents: bootWith({
					"fixture-first": { retries: 1 },
					"fixture-second": { retries: 1 },
					"legacy-second": { retries: 2, label: "x" },
					"legacy-first": { retries: 3 },
				}),
			}),
		);

		expect(err.details).toMatchObject({
			relocated: [
				{ module: "fixture-first", from: "legacy-first.retries", to: "fixture-first.retries" },
				{ module: "fixture-second", from: "legacy-second.retries", to: "fixture-second.retries" },
				{ module: "fixture-second", from: "legacy-second.label", to: "fixture-second.label" },
			],
		});
		expect(err.message).toContain("Configuration sets 3 path(s) that moved:");
		for (const sentence of [
			"legacy-first.retries has moved to fixture-first.retries; see CHANGELOG.",
			"legacy-second.retries has moved to fixture-second.retries; see CHANGELOG.",
			"legacy-second.label has moved to fixture-second.label; see CHANGELOG.",
		]) {
			expect(err.message).toContain(sentence);
		}
	});

	it("refuses at stage 1 a new path at or under its own old path: a key written right would be refused", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, at: "legacy", relocatedFrom: { "legacy.a": "a.b" } },
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ legacy: { retries: 1 } }),
			}),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-relocating",
			relocatedFrom: "legacy.a",
			problem: expect.stringContaining("legacy.a.b"),
		});
	});

	it.each([
		["is", ["fixture-relocating"], "it is the path the section is read at"],
		["holds", ["legacy"], "it holds the path the section is read at"],
	])("says an old path %s the section's own path", async (_label, relocatedFrom, words) => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				...(relocatedFrom[0] === "legacy" ? { at: "legacy.fixture" } : {}),
				relocatedFrom,
			},
		});

		const err = await refusal(
			createApp({ modules: [relocating], bootstrapComponents: bootWith(current) }),
		);

		expect(err.details).toMatchObject({ problem: expect.stringContaining(words) });
	});
});

describe("a relocated path — a chain: a new path that another relocation refuses in turn", () => {
	it("refuses a new path at another of the module's old paths, naming both", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				at: "current",
				relocatedFrom: { "legacy.a": "b", "current.b": "c" },
			},
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ current: { retries: 1 } }),
			}),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			reason: "module-section-path-invalid",
			module: "fixture-relocating",
			relocatedFrom: "legacy.a",
		});
		const problem = (err.details as { problem?: string }).problem ?? "";
		expect(problem).toContain('"current.b"');
		expect(problem).toContain('"fixture-relocating"');
	});

	it("refuses a new path that holds another of the module's old paths", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				at: "current",
				relocatedFrom: { legacy: "", "current.b": "c" },
			},
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ current: { retries: 1 } }),
			}),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-relocating",
			relocatedFrom: "legacy",
			problem: expect.stringContaining('"current.b"'),
		});
	});

	it("refuses a new path that holds its own old path: a key moved up could land under it", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: { schema: RetrySection, at: "current", relocatedFrom: { "current.b": "" } },
		});

		const err = await refusal(
			createApp({
				modules: [relocating],
				bootstrapComponents: bootWith({ current: { retries: 1 } }),
			}),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-relocating",
			relocatedFrom: "current.b",
			problem: expect.stringContaining("holds the old path"),
		});
	});

	const first = defineModule({
		name: "fixture-first",
		section: { schema: RetrySection, at: "first", relocatedFrom: { "legacy.x": "x" } },
	});
	const second = defineModule({
		name: "fixture-second",
		section: { schema: RetrySection, relocatedFrom: ["first.x"] },
	});
	const hoisting = defineModule({
		name: "fixture-first",
		section: { schema: RetrySection, at: "first", relocatedFrom: ["legacy-first"] },
	});
	const config = { first: { retries: 1 }, "fixture-second": { retries: 1 } };

	it.each([
		["at another module's old path, loaded after it", [first, second]],
		["at another module's old path, loaded before it", [second, first]],
		["over another module's old path", [hoisting, second]],
	] as const)("refuses a new path %s, naming both modules", async (_label, modules) => {
		const err = await refusal(
			createApp({ modules: [...modules], bootstrapComponents: bootWith(config) }),
		);

		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.details).toMatchObject({
			module: "fixture-first",
			relocatedFrom: modules.includes(first) ? "legacy.x" : "legacy-first",
		});
		const problem = (err.details as { problem?: string }).problem ?? "";
		expect(problem).toContain('"first.x"');
		expect(problem).toContain('"fixture-second"');
	});

	it("lets a key be renamed inside the section, and a removed key name any path", async () => {
		const relocating = defineModule({
			name: "fixture-relocating",
			section: {
				schema: RetrySection,
				at: "current",
				relocatedFrom: {
					"current.max-retries": "retries",
					"legacy.gone": null,
					"current.gone": null,
				},
			},
		});

		const handle = await createApp({
			modules: [relocating],
			bootstrapComponents: bootWith({ current: { retries: 1 } }),
		});
		await handle.dispose();
	});
});
