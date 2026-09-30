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
 * `renamedVariableProblems`, on core's testing entry: the bindings every
 * declared rename needs across the layers a composition ships. Each old and
 * new name is captured in `renamed-variables` (`null` unset, the string
 * set); an old name is bound nowhere else; a new name is bound at its path.
 * `packageReferenceProblems` holds a package's own reference to it.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "#/modules/manifest/index.mjs";
import { packageReferenceProblems, renamedVariableProblems } from "#/testing/index.mjs";

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

/** `text` in a file of its own. */
function layer(text: string): string {
	const file = join(mkdtempSync(join(tmpdir(), "renamed-variables-")), "reference.conf");
	writeFileSync(file, text);
	return file;
}

/** HOCON capturing each of `names`: `null`, then `${?NAME}`. */
const capture = (...names: string[]): string =>
	`renamed-variables {\n${names.map((name) => `  ${name} = null\n  ${name} = \${?${name}}\n`).join("")}}\n`;

const SECTION = "fixture-renaming {\n  retries = 3\n  retries = ${?FIXTURE_RENAMING_RETRIES}\n}\n";

const renaming = (renamedVariables: Record<string, string>, reference?: string) =>
	defineModule({
		name: "fixture-renaming",
		section: {
			schema: z.object({ retries: z.coerce.number() }),
			relocatedFrom: { legacy: "", "legacy-gone.flag": null },
			renamedVariables,
			...(reference === undefined ? {} : { reference: pathToFileURL(reference) }),
		},
	});

describe("renamedVariableProblems", () => {
	it("finds nothing wrong when both names are captured, the new one bound at its path and the old one nowhere else", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" })],
				layers: [reference],
				read,
			}),
		).toEqual([]);
	});

	it("names a name no layer captures, and one captured without its null", () => {
		const reference = layer(
			`${SECTION}renamed-variables {\n  FIXTURE_RENAMING_RETRIES = \${?FIXTURE_RENAMING_RETRIES}\n}\n`,
		);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" })],
				layers: [reference],
				read,
			}),
		).toEqual([
			expect.stringMatching(/^module "fixture-renaming": FIXTURE_RENAMING_RETRIES is not captured/),
			expect.stringMatching(/^module "fixture-renaming": LEGACY_RETRIES is not captured/),
		]);
	});

	it("names a new name bound at no layer's path: a typo in the old path derives a name nothing reads", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETIRES")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retires" })],
				layers: [reference],
				read,
			}),
		).toEqual([
			'module "fixture-renaming": FIXTURE_RENAMING_RETIRES is bound at fixture-renaming.retires in no layer',
		]);
	});

	it("names an old name another layer still binds, as a declaration of a live variable would", () => {
		const reference = layer(`${SECTION}${capture("OTHER_SETTING", "FIXTURE_RENAMING_RETRIES")}`);
		const other = layer("other { setting = ${?OTHER_SETTING} }\n");

		expect(
			renamedVariableProblems({
				modules: [renaming({ OTHER_SETTING: "legacy.retries" })],
				layers: [reference, other],
				read,
			}),
		).toEqual([
			`module "fixture-renaming": OTHER_SETTING, declared renamed, is bound at other.setting in ${other}`,
		]);
	});

	it("holds a removed key's variable to its capture alone", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_GONE_FLAG")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_GONE_FLAG: "legacy-gone.flag" })],
				layers: [reference],
				read,
			}),
		).toEqual([]);
	});

	it("holds core's own section's renames when given them", () => {
		const reference = layer(`${capture("DEPLOYMENT_MODE")}`);

		expect(
			renamedVariableProblems({
				modules: [],
				core: {
					relocatedFrom: { deployment: "deployment" },
					renamedVariables: { DEPLOYMENT_MODE: "deployment.mode" },
				},
				layers: [reference],
				read,
			}),
		).toEqual([
			'module "core": CORE_DEPLOYMENT_MODE is bound at core.deployment.mode in no layer',
			expect.stringMatching(/^module "core": CORE_DEPLOYMENT_MODE is not captured/),
		]);
	});
});

describe("packageReferenceProblems — renamed variables", () => {
	it("holds the package's reference to its modules' renames, and owns the captures of names they declare", () => {
		const good = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES")}`);
		expect(
			packageReferenceProblems({
				reference: pathToFileURL(good),
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" }, good)],
				read,
			}),
		).toEqual([]);

		const bad = layer(`${SECTION}${capture("LEGACY_RETRIES", "STRAY_NAME")}`);
		expect(
			packageReferenceProblems({
				reference: pathToFileURL(bad),
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" }, bad)],
				read,
			}),
		).toEqual([
			expect.stringMatching(/^module "fixture-renaming": FIXTURE_RENAMING_RETRIES is not captured/),
			"renamed-variables.STRAY_NAME: no module declaring this reference declares STRAY_NAME renamed",
		]);
	});
});
