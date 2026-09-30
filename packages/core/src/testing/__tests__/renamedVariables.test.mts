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
 * set) by the declaring module's own `section.reference` (core's own
 * `reference.conf` for core), and by no other layer; an old name is bound
 * nowhere else; a new name is bound at its path. `packageReferenceProblems`
 * holds a package's own reference to it. `renamedVariableCaptures` derives
 * what a resolution under an environment captures, for a configuration built
 * by hand.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { CORE_RELOCATIONS } from "#/config/core-relocations.mjs";
import { coreReference } from "#/config/references.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "#/ratelimit/module.mjs";
import {
	packageReferenceProblems,
	renamedVariableCaptures,
	renamedVariableProblems,
} from "#/testing/index.mjs";

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

const SECTION = `fixture-renaming {\n  retries = 3\n  retries = \${?FIXTURE_RENAMING_RETRIES}\n}\n`;

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
	it("finds nothing wrong when the module's own reference captures both names, binds the new one at its path, and binds the old one nowhere else", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" }, reference)],
				layers: [reference],
				read,
			}),
		).toEqual([]);
	});

	it("names a name the module's reference does not capture, and one it captures without its null", () => {
		const reference = layer(
			`${SECTION}renamed-variables {\n  FIXTURE_RENAMING_RETRIES = \${?FIXTURE_RENAMING_RETRIES}\n}\n`,
		);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" }, reference)],
				layers: [reference],
				read,
			}),
		).toEqual([
			expect.stringMatching(
				/^module "fixture-renaming": FIXTURE_RENAMING_RETRIES is not captured by its section\.reference/,
			),
			expect.stringMatching(
				/^module "fixture-renaming": LEGACY_RETRIES is not captured by its section\.reference/,
			),
		]);
	});

	it("names a module that declares renames and no section.reference to capture them", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" })],
				layers: [reference],
				read,
			}),
		).toEqual([
			expect.stringMatching(/^[^:]*reference\.conf: captures FIXTURE_RENAMING_RETRIES,/),
			expect.stringMatching(/^[^:]*reference\.conf: captures LEGACY_RETRIES,/),
			'module "fixture-renaming": declares renamed variables and no section.reference, whose file captures them',
		]);
	});

	it("names a layer other than the declaring reference that captures a name, as an operator's file overriding a capture would", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES")}`);
		const application = layer("renamed-variables { LEGACY_RETRIES = null }\n");

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retries" }, reference)],
				layers: [application, reference],
				read,
			}),
		).toEqual([
			`${application}: captures LEGACY_RETRIES, which no module whose section.reference it is declares renamed`,
		]);
	});

	it("names a new name bound at no layer's path: a typo in the old path derives a name nothing reads", () => {
		const reference = layer(`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETIRES")}`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ LEGACY_RETRIES: "legacy.retires" }, reference)],
				layers: [reference],
				read,
			}),
		).toEqual([
			'module "fixture-renaming": FIXTURE_RENAMING_RETIRES is bound at fixture-renaming.retires in no layer',
		]);
	});

	it("names an old name another layer still binds, as a declaration of a live variable would", () => {
		const reference = layer(`${SECTION}${capture("OTHER_SETTING", "FIXTURE_RENAMING_RETRIES")}`);
		const other = layer(`other { setting = \${?OTHER_SETTING} }\n`);

		expect(
			renamedVariableProblems({
				modules: [renaming({ OTHER_SETTING: "legacy.retries" }, reference)],
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
				modules: [renaming({ LEGACY_GONE_FLAG: "legacy-gone.flag" }, reference)],
				layers: [reference],
				read,
			}),
		).toEqual([]);
	});

	it("holds core's own section's and core's modules' renames to core's own reference.conf, which captures the shipped ones", () => {
		const core = fileURLToPath(coreReference());

		expect(
			renamedVariableProblems({
				modules: [memoryRateLimiterModule],
				core: CORE_RELOCATIONS,
				layers: [core],
				read,
			}),
		).toEqual([]);
	});

	it("names a rename of core's own section that core's own reference.conf neither binds nor captures", () => {
		const core = fileURLToPath(coreReference());

		const problems = renamedVariableProblems({
			modules: [memoryRateLimiterModule],
			core: {
				...CORE_RELOCATIONS,
				renamedVariables: { ...CORE_RELOCATIONS.renamedVariables, LEGACY_CORE_FLAG: "core.flag" },
			},
			layers: [core],
			read,
		});

		expect(problems).toEqual([
			'module "core": CORE_FLAG is bound at core.flag in no layer',
			expect.stringMatching(
				/^module "core": CORE_FLAG is not captured by core's own reference\.conf/,
			),
			expect.stringMatching(
				/^module "core": LEGACY_CORE_FLAG is not captured by core's own reference\.conf/,
			),
		]);
	});
});

describe("renamedVariableCaptures", () => {
	it("is what a resolution under the environment captures: each declared name's value, or null when unset", () => {
		const reference = layer(
			`${SECTION}${capture("LEGACY_RETRIES", "FIXTURE_RENAMING_RETRIES", "LEGACY_GONE_FLAG")}`,
		);
		const modules = [
			renaming(
				{ LEGACY_RETRIES: "legacy.retries", LEGACY_GONE_FLAG: "legacy-gone.flag" },
				reference,
			),
		];
		const env = { LEGACY_RETRIES: "5", LEGACY_GONE_FLAG: "", UNRELATED: "x" };

		expect(renamedVariableCaptures({ modules, env })).toEqual({
			LEGACY_RETRIES: "5",
			FIXTURE_RENAMING_RETRIES: null,
			LEGACY_GONE_FLAG: "",
		});
		expect(renamedVariableCaptures({ modules, env })).toEqual(
			(read(reference, env) as { "renamed-variables": unknown })["renamed-variables"],
		);
	});

	it("captures core's own section's names when given them", () => {
		expect(
			renamedVariableCaptures({
				modules: [],
				core: CORE_RELOCATIONS,
				env: { DEPLOYMENT_MODE: "multi" },
			}),
		).toEqual({ DEPLOYMENT_MODE: "multi", CORE_DEPLOYMENT_MODE: null });
	});
});

describe("packageReferenceProblems — renamed variables", () => {
	it("holds the package's reference to its modules' renames, and to capturing no other name", () => {
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
			`${bad}: captures STRAY_NAME, which no module whose section.reference it is declares renamed`,
			expect.stringMatching(/^module "fixture-renaming": FIXTURE_RENAMING_RETRIES is not captured/),
		]);
	});
});
