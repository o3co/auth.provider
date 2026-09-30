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
 * A variable renamed with a move, through the template's own reading: its
 * layers read once under one environment (`readOwnLayers`) and resolved over
 * every loaded module's `reference.conf`, which captures what that
 * resolution saw of each renamed name. A fixture module moved two keys out of
 * `legacy`, outside its own section, and renamed their variables
 * (`section.renamedVariables`); its `reference.conf` binds only the new
 * names, at the new paths, and captures the old and new ones. For each
 * rename: the old name alone refuses boot, naming the new path and the new
 * variable; old and new at different values refuse; at the same value, the
 * composition boots and reads it; the new name alone boots as usual.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { BootError, defineModule } from "@o3co/auth-provider-core";
import {
	type ComposeOptions,
	type Composition,
	compose,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";

/** The fixture package's `reference.conf`: the section's defaults and the new names, bound at the new paths alone. */
const REFERENCE: URL = (() => {
	const file = join(mkdtempSync(join(tmpdir(), "renamed-variables-")), "reference.conf");
	writeFileSync(
		file,
		`fixture-renaming {
  retries = 3
  retries = \${?FIXTURE_RENAMING_RETRIES}
  label = \${?FIXTURE_RENAMING_LABEL}
}
renamed-variables {
  LEGACY_RETRIES = null
  LEGACY_RETRIES = \${?LEGACY_RETRIES}
  FIXTURE_RENAMING_RETRIES = null
  FIXTURE_RENAMING_RETRIES = \${?FIXTURE_RENAMING_RETRIES}
  LEGACY_LABEL = null
  LEGACY_LABEL = \${?LEGACY_LABEL}
  FIXTURE_RENAMING_LABEL = null
  FIXTURE_RENAMING_LABEL = \${?FIXTURE_RENAMING_LABEL}
}
`,
	);
	return pathToFileURL(file);
})();

const renaming = defineModule({
	name: "fixture-renaming",
	section: {
		schema: z.object({
			retries: z.coerce.number().int().positive(),
			label: z.string().optional(),
		}),
		reference: REFERENCE,
		relocatedFrom: { "legacy.retries": "retries", "legacy.label": "label" },
		renamedVariables: { LEGACY_RETRIES: "legacy.retries", LEGACY_LABEL: "legacy.label" },
	},
});

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** The template's composition with the fixture module added, under `env` beside the deployment's own. */
function options(env: Record<string, string>, more: ComposeOptions = {}): ComposeOptions {
	return { env: { ...SINGLE_ENV, ...env }, extraModules: () => [renaming], ...more };
}

/** Boots, and remembers the composition so `afterEach` disposes it. */
async function boot(env: Record<string, string>): Promise<Composition> {
	current = await compose(options(env));
	return current;
}

/** What boot refused with. */
async function refused(env: Record<string, string>, more: ComposeOptions = {}): Promise<BootError> {
	try {
		current = await compose(options(env, more));
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the composition booted");
}

/** The fixture's section as boot parsed it. */
const sectionOf = (composition: Composition): unknown =>
	(composition.config as unknown as Record<string, unknown>)["fixture-renaming"];

const RENAMES = [
	{
		old: "LEGACY_RETRIES",
		renamed: "FIXTURE_RENAMING_RETRIES",
		path: "fixture-renaming.retries",
		key: "retries",
		value: "5",
		read: 5,
	},
	{
		old: "LEGACY_LABEL",
		renamed: "FIXTURE_RENAMING_LABEL",
		path: "fixture-renaming.label",
		key: "label",
		value: "blue",
		read: "blue",
	},
] as const;

describe.each(RENAMES)(
	"$old, renamed $renamed with a key moved in from outside its module's section",
	({ old, renamed, path, key, value, read }) => {
		it("set alone: refused, naming the new path and the new variable", async () => {
			const err = await refused({ [old]: value });

			expect(err.reason).toBe("environment-variable-renamed");
			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module: "fixture-renaming", from: old, to: renamed, path, state: "unset" }],
			});
			for (const named of [old, renamed, path]) expect(err.message).toContain(named);
		});

		it("set beside the new name at a different value: refused, naming both variables and neither value", async () => {
			const err = await refused({ [old]: "old-value-5e2d", [renamed]: "new-value-c81a" });

			expect(err.reason).toBe("environment-variable-renamed");
			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module: "fixture-renaming", from: old, to: renamed, path, state: "different" }],
			});
			expect(err.message).toContain(old);
			expect(err.message).toContain(renamed);
			expect(err.message).not.toContain("old-value-5e2d");
			expect(err.message).not.toContain("new-value-c81a");
		});

		it("set beside the new name at the same value: boots, and the module reads it at the new path", async () => {
			const composition = await boot({ [old]: value, [renamed]: value });

			expect(sectionOf(composition)).toMatchObject({ [key]: read });
		});

		it("unset, with the new name set: boots, and the module reads it", async () => {
			const composition = await boot({ [renamed]: value });

			expect(sectionOf(composition)).toMatchObject({ [key]: read });
		});
	},
);

describe("a renamed variable, through the template's reading — more", () => {
	it("an old name set alone to the value its new path defaults to is refused: a default is not the new name set", async () => {
		const err = await refused({ LEGACY_RETRIES: "3" });

		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_RETRIES", state: "unset" }],
		});
	});

	it("an old name set to the empty string alone is refused", async () => {
		const err = await refused({ LEGACY_LABEL: "" });

		expect(err.details).toMatchObject({
			renamed: [{ from: "LEGACY_LABEL", state: "unset" }],
		});
	});

	it("both names set to the empty string boot, and the module reads the empty string", async () => {
		const composition = await boot({ LEGACY_LABEL: "", FIXTURE_RENAMING_LABEL: "" });

		expect(sectionOf(composition)).toMatchObject({ label: "" });
	});

	it("both renames of the module broken at once: one refusal names both, in the order declared", async () => {
		const err = await refused({
			LEGACY_LABEL: "a",
			FIXTURE_RENAMING_LABEL: "b",
			LEGACY_RETRIES: "5",
		});

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				expect.objectContaining({ from: "LEGACY_RETRIES", state: "unset" }),
				expect.objectContaining({ from: "LEGACY_LABEL", state: "different" }),
			],
		});
	});

	it("the old path written in the operator's own layer is still refused when both variables agree", async () => {
		const err = await refused(
			{ LEGACY_RETRIES: "5", FIXTURE_RENAMING_RETRIES: "5" },
			{ operatorHocon: "legacy.retries = 5\n" },
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
