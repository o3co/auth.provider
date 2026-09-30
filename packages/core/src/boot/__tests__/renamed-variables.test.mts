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
 * An environment variable renamed with a move. A loaded module's
 * `section.renamedVariables` — or core's own, for its section — maps each old
 * name to the old path it was bound to; the new name is the variable the
 * path's new place is bound to. What the resolution saw of both is captured in
 * the configuration's reserved `renamed-variables` section (each name `null`,
 * then `${?NAME}`, in the package's `reference.conf`): the old name set and the
 * new one unset, or set to a different string, refuses boot with
 * `environment-variable-renamed`; the two set to the same string boot; a name
 * the configuration does not capture refuses boot. The section is removed
 * before the configuration is parsed. A manifest that declares a rename boot
 * cannot hold is refused at stage 1 (`module-section-path-invalid`).
 */

import { parseString } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import type { Module } from "../../modules/manifest/module-spec.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { AppHandle, BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";
import { validateManifests } from "../validate-manifests.mjs";

const RetrySection = z.object({
	retries: z.coerce.number().int().positive(),
	label: z.string().optional(),
});

/** HOCON capturing each of `names` as the resolution sees it: `null` when unset. */
const capture = (...names: string[]): string =>
	`renamed-variables {\n${names.map((name) => `  ${name} = null\n  ${name} = \${?${name}}\n`).join("")}}\n`;

/** The fixture's `reference.conf`: its section's defaults, the new names at the new paths, and the captures. */
const REFERENCE = `
fixture-renaming {
  retries = 3
  retries = \${?FIXTURE_RENAMING_RETRIES}
  label = \${?FIXTURE_RENAMING_LABEL}
}
${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES", "LEGACY_LABEL", "FIXTURE_RENAMING_LABEL")}`;

/** Two keys moved out of `legacy`, outside the module's own section, each with its variable renamed. */
const renaming = (seen?: (section: z.output<typeof RetrySection>) => void) =>
	defineModule({
		name: "fixture-renaming",
		section: {
			schema: RetrySection,
			relocatedFrom: { "legacy.retries": "retries", "legacy.label": "label" },
			renamedVariables: { LEGACY_RETRIES: "legacy.retries", LEGACY_LABEL: "legacy.label" },
		},
		contributes: {
			grantMiddleware: [
				({ section }) => {
					seen?.(section);
					return null;
				},
			],
		},
	});

/** Core's valid configuration, with `operator` HOCON over `reference`, resolved under `env`. */
function resolved(
	env: Record<string, string>,
	operator = "",
	reference = REFERENCE,
): Record<string, unknown> {
	const layered = parseString(operator, { env }).withFallback(parseString(reference, { env }));
	return { ...makeValidCoreConfig(), ...(layered.toObject() as Record<string, unknown>) };
}

const bootstrap = (config: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
	({ config: config as never, pathResolver: (s: string) => s, ...extra }) as BootstrapMap;

/** Boots `modules` over the configuration resolved under `env`. */
function boot(
	env: Record<string, string>,
	modules: readonly Module[] = [renaming()],
	operator = "",
	reference = REFERENCE,
): Promise<AppHandle> {
	return createApp({
		modules,
		bootstrapComponents: bootstrap(resolved(env, operator, reference)),
	});
}

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<AppHandle>): Promise<BootError> {
	try {
		const handle = await promise;
		await handle.dispose();
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("a renamed variable — the old name set", () => {
	it("alone: refused, naming the old variable, the new one and the new path", async () => {
		const err = await refusal(boot({ LEGACY_RETRIES: "5" }));

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "fixture-renaming",
					from: "LEGACY_RETRIES",
					to: "FIXTURE_RENAMING_RETRIES",
					path: "fixture-renaming.retries",
					state: "unset",
				},
			],
		});
		expect(err.message).toContain("LEGACY_RETRIES");
		expect(err.message).toContain("FIXTURE_RENAMING_RETRIES");
		expect(err.message).toContain("fixture-renaming.retries");
	});

	it("alone, with the value the new path defaults to: refused, a default is not the new name set", async () => {
		const err = await refusal(boot({ LEGACY_RETRIES: "3" }));

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_RETRIES", state: "unset" }] });
	});

	it("with the new name set to a different value: refused, naming both variables and neither value", async () => {
		const err = await refusal(
			boot({ LEGACY_LABEL: "old-label-4f1c", FIXTURE_RENAMING_LABEL: "new-label-9b2e" }),
		);

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "fixture-renaming",
					from: "LEGACY_LABEL",
					to: "FIXTURE_RENAMING_LABEL",
					path: "fixture-renaming.label",
					state: "different",
				},
			],
		});
		expect(err.message).toContain("LEGACY_LABEL");
		expect(err.message).toContain("FIXTURE_RENAMING_LABEL");
		for (const value of ["old-label-4f1c", "new-label-9b2e"]) {
			expect(err.message).not.toContain(value);
			expect(JSON.stringify(err.details)).not.toContain(value);
		}
	});

	it("with the new name set to the same value: boots, and the module reads it at the new path", async () => {
		let seen: unknown;
		const handle = await boot({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5" }, [
			renaming((section) => (seen = section)),
		]);
		await handle.dispose();

		expect(seen).toEqual({ retries: 5 });
	});

	it("compares the raw strings: the same number written differently is a different value", async () => {
		const err = await refusal(boot({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "05" }));

		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_RETRIES", state: "different" }],
		});
	});
});

describe("a renamed variable — the old name unset", () => {
	it("with the new name set: boots, and the module reads it", async () => {
		let seen: unknown;
		const handle = await boot({ FIXTURE_RENAMING_LABEL: "blue" }, [
			renaming((section) => (seen = section)),
		]);
		await handle.dispose();

		expect(seen).toEqual({ retries: 3, label: "blue" });
	});

	it("with neither name set: boots on the new path's default", async () => {
		let seen: unknown;
		const handle = await boot({}, [renaming((section) => (seen = section))]);
		await handle.dispose();

		expect(seen).toEqual({ retries: 3 });
	});
});

describe("a renamed variable — an empty value is a value", () => {
	it("an old name set to the empty string alone is refused", async () => {
		const err = await refusal(boot({ LEGACY_LABEL: "" }));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_LABEL", state: "unset" }] });
	});

	it("an old name set to the empty string beside a new name set to a value is refused", async () => {
		const err = await refusal(boot({ LEGACY_LABEL: "", FIXTURE_RENAMING_LABEL: "blue" }));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_LABEL", state: "different" }] });
	});

	it("both names set to the empty string boot, and the module reads the empty string", async () => {
		let seen: unknown;
		const handle = await boot({ LEGACY_LABEL: "", FIXTURE_RENAMING_LABEL: "" }, [
			renaming((section) => (seen = section)),
		]);
		await handle.dispose();

		expect(seen).toEqual({ retries: 3, label: "" });
	});
});

describe("a renamed variable — what the resolution saw, not the process's environment", () => {
	it("refuses an old name the resolution saw in an overlay the process's environment lacks", async () => {
		const overlay = { ...process.env, LEGACY_RETRIES: "5" } as Record<string, string>;

		const err = await refusal(boot(overlay));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_RETRIES", state: "unset" }] });
	});

	it("refuses an old name the resolution saw alone, though the process's environment sets both to it", async () => {
		vi.stubEnv("LEGACY_RETRIES", "5");
		vi.stubEnv("FIXTURE_RENAMING_RETRIES", "5");

		const err = await refusal(boot({ LEGACY_RETRIES: "5" }));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_RETRIES", state: "unset" }] });
	});

	it("boots when the resolution saw both names agree, though the process's environment sets the old one alone", async () => {
		vi.stubEnv("LEGACY_RETRIES", "5");

		const handle = await boot({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5" });
		await handle.dispose();
	});
});

describe("a renamed variable — the capture", () => {
	it("is removed before the configuration is parsed: the config slot has none, and it is named as no ignored section", async () => {
		const warn = vi.fn();
		const logger = { trace: vi.fn(), debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() };
		const handle = await createApp({
			modules: [renaming()],
			bootstrapComponents: bootstrap(
				resolved({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5" }),
				{
					logger: { ...logger, fatal: vi.fn(), child: () => logger },
				},
			),
		});
		const config = handle.components.config as unknown as Record<string, unknown>;
		await handle.dispose();

		expect(config).not.toHaveProperty("renamed-variables");
		expect(JSON.stringify(warn.mock.calls)).not.toContain("renamed-variables");
	});

	it("refuses a configuration that captures neither name, as one no reference.conf capturing them was layered under", async () => {
		const err = await refusal(
			boot({ LEGACY_RETRIES: "5" }, [renaming()], "", "fixture-renaming { retries = 3 }"),
		);

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: [
				{ from: "LEGACY_RETRIES", to: "FIXTURE_RENAMING_RETRIES", state: "uncaptured" },
				{ from: "LEGACY_LABEL", to: "FIXTURE_RENAMING_LABEL", state: "uncaptured" },
			],
		});
		expect(err.message).toContain("renamed-variables");
	});

	it("refuses a rename whose new name alone is not captured", async () => {
		const reference = `fixture-renaming { retries = 3 }\n${capture("LEGACY_RETRIES", "LEGACY_LABEL", "FIXTURE_RENAMING_LABEL")}`;

		const err = await refusal(boot({}, [renaming()], "", reference));

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [expect.objectContaining({ from: "LEGACY_RETRIES", state: "uncaptured" })],
		});
	});

	it("refuses a captured value that is neither null nor a string", async () => {
		const err = await refusal(boot({}, [renaming()], "renamed-variables.LEGACY_RETRIES = 5\n"));

		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_RETRIES", state: "uncaptured" }],
		});
	});

	it("is removed from a composition whose modules declare no rename, which boots", async () => {
		const unrelated = defineModule({
			name: "fixture-unrelated",
			section: { schema: RetrySection },
		});
		const handle = await createApp({
			modules: [unrelated],
			bootstrapComponents: bootstrap({
				...makeValidCoreConfig(),
				"fixture-unrelated": { retries: 1 },
				"renamed-variables": { LEGACY_RETRIES: "5" },
			}),
		});
		const config = handle.components.config as unknown as Record<string, unknown>;
		await handle.dispose();

		expect(config).not.toHaveProperty("renamed-variables");
	});
});

describe("a renamed variable — more", () => {
	it("names every rename the environment breaks, in the module's declaration order, in one refusal", async () => {
		const err = await refusal(
			boot({ LEGACY_LABEL: "a", FIXTURE_RENAMING_LABEL: "b", LEGACY_RETRIES: "5" }),
		);

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				expect.objectContaining({ from: "LEGACY_RETRIES", state: "unset" }),
				expect.objectContaining({ from: "LEGACY_LABEL", state: "different" }),
			],
		});
		expect(err.message).toContain("2 variable(s)");
	});

	it("names the renames of several modules in module order", async () => {
		const second = defineModule({
			name: "fixture-second",
			section: {
				schema: RetrySection,
				relocatedFrom: { "older.retries": "retries" },
				renamedVariables: { OLDER_RETRIES: "older.retries" },
			},
		});
		const reference = `${REFERENCE}\nfixture-second { retries = 1 }\n${capture("OLDER_RETRIES", "FIXTURE_SECOND_RETRIES")}`;
		const env = { LEGACY_LABEL: "a", OLDER_RETRIES: "2" };
		const order = async (modules: readonly Module[]) =>
			(
				(await refusal(boot(env, modules, "", reference))).details as unknown as {
					renamed: { from: string }[];
				}
			).renamed.map(({ from }) => from);

		expect(await order([renaming(), second])).toEqual(["LEGACY_LABEL", "OLDER_RETRIES"]);
		expect(await order([second, renaming()])).toEqual(["OLDER_RETRIES", "LEGACY_LABEL"]);
	});

	it("a rename that agrees beside one that does not: only the one that does not is named", async () => {
		const err = await refusal(
			boot({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5", LEGACY_LABEL: "a" }),
		);

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [expect.objectContaining({ from: "LEGACY_LABEL", state: "unset" })],
		});
	});

	it("still refuses the old path written in the configuration when both variables agree", async () => {
		const err = await refusal(
			boot(
				{ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5" },
				[renaming()],
				"legacy.retries = 5\n",
			),
		);

		expect(err.reason).toBe("config-path-relocated");
		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "fixture-renaming",
					from: "legacy.retries",
					to: "fixture-renaming.retries",
					environmentVariable: "FIXTURE_RENAMING_RETRIES",
				},
			],
		});
	});
});

describe("a renamed variable — a key that stays where it is", () => {
	const inPlace = defineModule({
		name: "fixture-in-place",
		section: {
			schema: RetrySection,
			renamedVariables: { FIXTURE_RETRY_COUNT: "fixture-in-place.retries" },
		},
	});
	const reference = `fixture-in-place {\n  retries = 3\n  retries = \${?FIXTURE_IN_PLACE_RETRIES}\n}\n${capture("FIXTURE_RETRY_COUNT", "FIXTURE_IN_PLACE_RETRIES")}`;

	it("is renamed to the variable its path in the module's own section is bound to: the old name alone is refused", async () => {
		const err = await refusal(boot({ FIXTURE_RETRY_COUNT: "5" }, [inPlace], "", reference));

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "fixture-in-place",
					from: "FIXTURE_RETRY_COUNT",
					to: "FIXTURE_IN_PLACE_RETRIES",
					path: "fixture-in-place.retries",
					state: "unset",
				},
			],
		});
	});

	it("boots with both names set to the same value", async () => {
		const handle = await boot(
			{ FIXTURE_RETRY_COUNT: "5", FIXTURE_IN_PLACE_RETRIES: "5" },
			[inPlace],
			"",
			reference,
		);
		const config = handle.components.config as unknown as Record<string, { retries?: unknown }>;
		await handle.dispose();

		expect(config["fixture-in-place"]?.retries).toBe(5);
	});
});

describe("a renamed variable — a key that was removed", () => {
	const removing = defineModule({
		name: "fixture-removing",
		section: {
			schema: RetrySection,
			relocatedFrom: { "legacy.gone": null },
			renamedVariables: { LEGACY_GONE: "legacy.gone" },
		},
	});
	const reference = `fixture-removing { retries = 3 }\n${capture("LEGACY_GONE")}`;

	it("refuses its variable whenever it is set, naming the removal and no value", async () => {
		const err = await refusal(boot({ LEGACY_GONE: "gone-value-7d3a" }, [removing], "", reference));

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{ module: "fixture-removing", from: "LEGACY_GONE", to: null, path: null, state: "removed" },
			],
		});
		expect(err.message).toContain("legacy.gone");
		expect(err.message).toContain("removed");
		expect(err.message).not.toContain("gone-value-7d3a");
	});

	it("refuses it set to the empty string", async () => {
		const err = await refusal(boot({ LEGACY_GONE: "" }, [removing], "", reference));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_GONE", state: "removed" }] });
	});

	it("boots with it unset", async () => {
		const handle = await boot({}, [removing], "", reference);
		await handle.dispose();
	});

	it("refuses a configuration that does not capture it", async () => {
		const err = await refusal(boot({}, [removing], "", "fixture-removing { retries = 3 }"));

		expect(err.details).toMatchObject({ renamed: [{ from: "LEGACY_GONE", state: "uncaptured" }] });
	});
});

describe("a renamed variable — core's own section", () => {
	/** The next move's shape: `deployment.mode` into core's section, `DEPLOYMENT_MODE` renamed with it. */
	const core = {
		relocatedFrom: { deployment: "deployment" },
		renamedVariables: { DEPLOYMENT_MODE: "deployment.mode" },
	} as const;
	const validate = (config: Record<string, unknown>) =>
		validateManifests({ modules: [], bootstrapComponents: bootstrap(config), core });
	const refusedBy = (config: Record<string, unknown>): BootError => {
		try {
			validate(config);
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("validation should have been refused");
	};
	const captured = (values: Record<string, string | null>) => ({
		...makeValidCoreConfig(),
		"renamed-variables": { DEPLOYMENT_MODE: null, CORE_DEPLOYMENT_MODE: null, ...values },
	});

	it("refuses its old name alone, naming core, the new name and the path in core's section", () => {
		const err = refusedBy(captured({ DEPLOYMENT_MODE: "multi" }));

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "core",
					from: "DEPLOYMENT_MODE",
					to: "CORE_DEPLOYMENT_MODE",
					path: "core.deployment.mode",
					state: "unset",
				},
			],
		});
	});

	it("accepts its old and new names set to the same value", () => {
		expect(() =>
			validate(captured({ DEPLOYMENT_MODE: "multi", CORE_DEPLOYMENT_MODE: "multi" })),
		).not.toThrow();
	});

	it("refuses its old path written in the configuration, naming core's section", () => {
		const err = refusedBy({ ...captured({}), deployment: { mode: "multi" } });

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core",
					from: "deployment.mode",
					to: "core.deployment.mode",
					environmentVariable: "CORE_DEPLOYMENT_MODE",
				},
			],
		});
	});

	it("holds its declaration as a module's: a name that did not change is refused", () => {
		expect(() =>
			validateManifests({
				modules: [],
				bootstrapComponents: bootstrap(captured({})),
				core: {
					relocatedFrom: { deployment: "deployment" },
					renamedVariables: { CORE_DEPLOYMENT_MODE: "deployment.mode" },
				},
			}),
		).toThrow(expect.objectContaining({ reason: "module-section-path-invalid" }));
	});
});

describe("a renamed variable — a manifest that declares one boot cannot hold", () => {
	const declaring = (
		renamedVariables: unknown,
		section: Record<string, unknown> = {},
		name = "fixture-renaming",
	) =>
		defineModule({
			name,
			section: {
				schema: RetrySection,
				relocatedFrom: { "legacy.retries": "retries", "legacy.gone": null },
				...section,
				renamedVariables: renamedVariables as never,
			},
		});

	const refusedAtStageOne = async (modules: readonly Module[]) => {
		const err = await refusal(
			createApp({ modules, bootstrapComponents: bootstrap({ ...makeValidCoreConfig() }) }),
		);
		expect(err.reason).toBe("module-section-path-invalid");
		expect(err.stage).toBe("validateManifests");
		return err;
	};

	it.each([
		["a list", ["LEGACY_RETRIES"], "a map from each old variable name"],
		["a Map", new Map([["LEGACY_RETRIES", "legacy.retries"]]), "a map from each old variable name"],
	] as const)(
		"refuses renamedVariables that is %s: a plain map, nothing read as one",
		async (_label, value, words) => {
			const err = await refusedAtStageOne([declaring(value)]);

			expect(err.details).toMatchObject({
				module: "fixture-renaming",
				renamedVariable: value,
				problem: expect.stringContaining(words),
			});
		},
	);

	it.each([
		[
			"a name that is not a variable's, as a path swapped for it would be",
			{ "legacy.retries": "LEGACY_RETRIES" },
			"legacy.retries",
			"variable name",
		],
		[
			"an old path with an empty key",
			{ LEGACY_RETRIES: "legacy..retries" },
			"LEGACY_RETRIES",
			"dot-separated path",
		],
		[
			"an old path that is not a string",
			{ LEGACY_RETRIES: 1 },
			"LEGACY_RETRIES",
			"dot-separated path",
		],
		[
			"an old path the section neither moved from nor holds",
			{ LEGACY_RETRIES: "elsewhere.retries" },
			"LEGACY_RETRIES",
			"relocatedFrom",
		],
		[
			"a name that did not change: the one its new path is bound to",
			{ FIXTURE_RENAMING_RETRIES: "legacy.retries" },
			"FIXTURE_RENAMING_RETRIES",
			"did not change",
		],
		[
			"a name that did not change, for a key that stays in place",
			{ FIXTURE_RENAMING_LABEL: "fixture-renaming.label" },
			"FIXTURE_RENAMING_LABEL",
			"did not change",
		],
	] as const)("refuses %s, naming the variable", async (_label, renamedVariables, named, words) => {
		const err = await refusedAtStageOne([declaring(renamedVariables)]);

		expect(err.details).toMatchObject({
			reason: "module-section-path-invalid",
			module: "fixture-renaming",
			renamedVariable: named,
			problem: expect.stringContaining(words),
		});
	});

	it.each([
		["moved", { LEGACY_RETRIES: "legacy.retries" }],
		["in place", { FIXTURE_RETRY_COUNT: "current.fixture.retries" }],
	])(
		"refuses a rename %s under a transitional section path, which no variable binds yet",
		async (_label, renamedVariables) => {
			const err = await refusedAtStageOne([declaring(renamedVariables, { at: "current.fixture" })]);

			expect(err.details).toMatchObject({
				module: "fixture-renaming",
				problem: expect.stringContaining("transitional"),
			});
		},
	);

	it("refuses a rename whose old path moved whole as the section: no variable binds a section", async () => {
		const err = await refusedAtStageOne([
			declaring({ LEGACY_FIXTURE: "legacy.fixture" }, { relocatedFrom: { "legacy.fixture": "" } }),
		]);

		expect(err.details).toMatchObject({
			module: "fixture-renaming",
			renamedVariable: "LEGACY_FIXTURE",
			problem: expect.stringContaining("the section itself"),
		});
	});

	it("refuses an old name another loaded module declares renamed too, naming both modules", async () => {
		const first = declaring({ LEGACY_RETRIES: "legacy.retries" });
		const second = defineModule({
			name: "fixture-second",
			section: {
				schema: RetrySection,
				relocatedFrom: { "older.retries": "retries" },
				renamedVariables: { LEGACY_RETRIES: "older.retries" },
			},
		});

		const err = await refusedAtStageOne([first, second]);

		expect(err.details).toMatchObject({
			module: "fixture-second",
			renamedVariable: "LEGACY_RETRIES",
		});
		const problem = (err.details as { problem?: string }).problem ?? "";
		expect(problem).toContain('"fixture-renaming"');
		expect(problem).toContain('"fixture-second"');
	});

	it("refuses an old name that is another rename's new name: setting that name would be refused", async () => {
		const first = declaring({ LEGACY_RETRIES: "legacy.retries" });
		const second = defineModule({
			name: "fixture-second",
			section: {
				schema: RetrySection,
				relocatedFrom: { "older.retries": "retries" },
				renamedVariables: { FIXTURE_RENAMING_RETRIES: "older.retries" },
			},
		});

		const err = await refusedAtStageOne([first, second]);

		expect(err.details).toMatchObject({
			module: "fixture-second",
			renamedVariable: "FIXTURE_RENAMING_RETRIES",
			problem: expect.stringContaining('"fixture-renaming"'),
		});
	});

	it("refuses a module whose section is read at the reserved renamed-variables", async () => {
		const reserved = defineModule({ name: "renamed-variables", section: { schema: RetrySection } });

		const err = await refusedAtStageOne([reserved]);

		expect(err.details).toMatchObject({
			module: "renamed-variables",
			problem: expect.stringContaining("reserved"),
		});
	});

	it("refuses an old path under the reserved renamed-variables", async () => {
		const err = await refusedAtStageOne([
			defineModule({
				name: "fixture-renaming",
				section: { schema: RetrySection, relocatedFrom: ["renamed-variables.LEGACY_RETRIES"] },
			}),
		]);

		expect(err.details).toMatchObject({
			module: "fixture-renaming",
			relocatedFrom: "renamed-variables.LEGACY_RETRIES",
			problem: expect.stringContaining("reserved"),
		});
	});

	it("reads a map with no prototype as a map", async () => {
		const renamedVariables: Record<string, string> = Object.assign(Object.create(null), {
			LEGACY_RETRIES: "legacy.retries",
		});
		const err = await refusal(
			createApp({
				modules: [declaring(renamedVariables)],
				bootstrapComponents: bootstrap({
					...makeValidCoreConfig(),
					"fixture-renaming": { retries: 1 },
					"renamed-variables": { LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: null },
				}),
			}),
		);

		expect(err.reason).toBe("environment-variable-renamed");
	});
});
