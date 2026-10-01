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
 * Every test file vitest collects in a package is compiled by that package's
 * test program. vitest's typecheck runs tsc on `tsconfig.test.json`, so a test
 * outside that program runs without its types ever being checked: a
 * `@ts-expect-error` or `satisfies` in it proves nothing.
 *
 * Each workspace under `packages/` declares a `tsconfig.test.json`. The files
 * vitest collects are asked of vitest itself, from the package's own config;
 * the program's files are asked of TypeScript, from the package's own
 * `tsconfig.test.json`. A collected file outside the program fails, naming
 * the package and the file. There is no list of exceptions.
 */

import { existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { createVitest } from "vitest/node";

const packagesDir = resolve(fileURLToPath(import.meta.url), "../../../..");

/** The workspaces under `packages/`: each directory that holds a package.json. */
const packages = readdirSync(packagesDir, { withFileTypes: true })
	.filter(
		(entry) => entry.isDirectory() && existsSync(join(packagesDir, entry.name, "package.json")),
	)
	.map((entry) => entry.name)
	.sort();

/** The files `tsconfig.test.json` hands tsc, as absolute paths. */
function programFiles(configPath: string): Set<string> {
	const parsed = ts.getParsedCommandLineOfConfigFile(
		configPath,
		{},
		{
			...ts.sys,
			onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
				throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));
			},
		},
	);
	if (parsed === undefined) throw new Error(`${configPath} could not be read`);
	if (parsed.errors.length > 0) {
		throw new Error(
			parsed.errors.map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n")).join("\n"),
		);
	}
	return new Set(parsed.fileNames.map((file) => resolve(file)));
}

/** The test files vitest collects under the package's own config, typecheck included. */
async function collectedFiles(root: string): Promise<string[]> {
	const vitest = await createVitest("test", { root, watch: false });
	try {
		const specifications = await vitest.globTestSpecifications();
		return [...new Set(specifications.map((specification) => resolve(specification.moduleId)))];
	} finally {
		await vitest.close();
	}
}

describe("every test file vitest collects is in its package's tsconfig.test.json", () => {
	it("finds the packages to check", () => {
		expect(packages).toContain("core");
	});

	it.each(packages)("%s", async (name) => {
		const root = join(packagesDir, name);
		const configPath = join(root, "tsconfig.test.json");
		expect(existsSync(configPath), `packages/${name} has no tsconfig.test.json`).toBe(true);

		const program = programFiles(configPath);
		const collected = await collectedFiles(root);
		expect(collected.length, `vitest collects no test file in packages/${name}`).toBeGreaterThan(0);
		const outside = collected
			.filter((file) => !program.has(file))
			.map((file) => file.slice(root.length + 1))
			.sort();
		expect(outside, `packages/${name}: collected by vitest, never compiled`).toEqual([]);
	});
});
