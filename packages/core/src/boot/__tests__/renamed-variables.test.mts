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
 * `section.renamedVariables` maps each old name to the old path it was bound
 * to; the new name is the variable the path's new place is bound to. Boot
 * reads both from the environment the configuration was resolved with
 * (`createApp`'s `environment`, the process's when unset): the old name set
 * and the new one unset, or set to a different string, refuses boot with
 * `environment-variable-renamed`; the two set to the same string boot. A
 * manifest that declares a rename boot cannot hold is refused at stage 1
 * (`module-section-path-invalid`).
 */

import { parseString } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { AppHandle, BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

const RetrySection = z.object({
	retries: z.coerce.number().int().positive(),
	label: z.string().optional(),
});

/** The fixture's defaults and the variables bound at its section, as its `reference.conf` would hold them. */
const REFERENCE = `
fixture-renaming {
  retries = 3
  retries = \${?FIXTURE_RENAMING_RETRIES}
  label = \${?FIXTURE_RENAMING_LABEL}
}
`;

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

/** Core's valid configuration, with `operator` HOCON over the fixture's reference, resolved under `env`. */
function resolved(env: Record<string, string>, operator = ""): Record<string, unknown> {
	const layered = parseString(operator, { env }).withFallback(parseString(REFERENCE, { env }));
	return { ...makeValidCoreConfig(), ...(layered.toObject() as Record<string, unknown>) };
}

const bootstrap = (config: Record<string, unknown>): BootstrapMap =>
	({ config: config as never, pathResolver: (s: string) => s }) as BootstrapMap;

/** Boots `modules` over the configuration resolved under `env`, with `env` as the environment. */
function boot(
	env: Record<string, string>,
	modules = [renaming()],
	operator = "",
): Promise<AppHandle> {
	return createApp({
		modules,
		bootstrapComponents: bootstrap(resolved(env, operator)),
		environment: env,
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
					newVariable: "unset",
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
		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_RETRIES", newVariable: "unset" }],
		});
	});

	it("with the new name set to a different value: refused, naming both variables and neither value", async () => {
		const err = await refusal(
			boot({ LEGACY_LABEL: "old-secret-value", FIXTURE_RENAMING_LABEL: "new-secret-value" }),
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
					newVariable: "different",
				},
			],
		});
		expect(err.message).toContain("LEGACY_LABEL");
		expect(err.message).toContain("FIXTURE_RENAMING_LABEL");
		expect(err.message).not.toContain("old-secret-value");
		expect(err.message).not.toContain("new-secret-value");
		expect(JSON.stringify(err.details)).not.toContain("secret-value");
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
			renamed: [{ from: "LEGACY_RETRIES", newVariable: "different" }],
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

		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_LABEL", newVariable: "unset" }],
		});
	});

	it("an old name set to the empty string beside a new name set to a value is refused", async () => {
		const err = await refusal(boot({ LEGACY_LABEL: "", FIXTURE_RENAMING_LABEL: "blue" }));

		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_LABEL", newVariable: "different" }],
		});
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

describe("a renamed variable — more", () => {
	it("names every rename the environment breaks, in the module's order, in one refusal", async () => {
		const err = await refusal(
			boot({ LEGACY_LABEL: "a", FIXTURE_RENAMING_LABEL: "b", LEGACY_RETRIES: "5" }),
		);

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				expect.objectContaining({ from: "LEGACY_RETRIES", newVariable: "unset" }),
				expect.objectContaining({ from: "LEGACY_LABEL", newVariable: "different" }),
			],
		});
		expect(err.message).toContain("2 variable(s)");
	});

	it("a rename that agrees beside one that does not: only the one that does not is named", async () => {
		const err = await refusal(
			boot({ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5", LEGACY_LABEL: "a" }),
		);

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [expect.objectContaining({ from: "LEGACY_LABEL", newVariable: "unset" })],
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

	it("a composition that does not load the renaming module boots with the old name set", async () => {
		const unrelated = defineModule({
			name: "fixture-unrelated",
			section: { schema: RetrySection },
		});
		const handle = await createApp({
			modules: [unrelated],
			bootstrapComponents: bootstrap({
				...makeValidCoreConfig(),
				"fixture-unrelated": { retries: 1 },
			}),
			environment: { LEGACY_RETRIES: "5" },
		});
		await handle.dispose();
	});

	it("reads the process's environment when the composition names none", async () => {
		vi.stubEnv("LEGACY_RETRIES", "5");
		const err = await refusal(
			createApp({ modules: [renaming()], bootstrapComponents: bootstrap(resolved({})) }),
		);

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_RETRIES", newVariable: "unset" }],
		});
	});

	it("reads only the environment the composition names, not the process's, when it names one", async () => {
		vi.stubEnv("LEGACY_RETRIES", "5");
		const handle = await boot({});
		await handle.dispose();
	});

	it("reads a variable only as the environment's own property", async () => {
		const inherited = Object.create({ LEGACY_RETRIES: "5" }) as Record<string, string>;
		const handle = await createApp({
			modules: [renaming()],
			bootstrapComponents: bootstrap(resolved({})),
			environment: inherited,
		});
		await handle.dispose();
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

	const refusedAtStageOne = async (modules: ReturnType<typeof declaring>[]) => {
		const config: Record<string, unknown> = { ...makeValidCoreConfig() };
		for (const module of modules) config[module.section?.at ?? module.name] = { retries: 1 };
		const err = await refusal(
			createApp({ modules, bootstrapComponents: bootstrap(config), environment: {} }),
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
			"an old path the section did not move from",
			{ LEGACY_RETRIES: "elsewhere.retries" },
			"LEGACY_RETRIES",
			"relocatedFrom",
		],
		[
			"an old path that was removed, not moved",
			{ LEGACY_GONE: "legacy.gone" },
			"LEGACY_GONE",
			"removed",
		],
		[
			"a name that did not change: the one its new path is bound to",
			{ FIXTURE_RENAMING_RETRIES: "legacy.retries" },
			"FIXTURE_RENAMING_RETRIES",
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

	it("refuses a rename whose new path lies under a transitional section path, which no variable binds yet", async () => {
		const err = await refusedAtStageOne([
			declaring({ LEGACY_RETRIES: "legacy.retries" }, { at: "current.fixture" }),
		]);

		expect(err.details).toMatchObject({
			module: "fixture-renaming",
			renamedVariable: "LEGACY_RETRIES",
			problem: expect.stringContaining("transitional"),
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
				}),
				environment: { LEGACY_RETRIES: "5" },
			}),
		);

		expect(err.reason).toBe("environment-variable-renamed");
	});
});
