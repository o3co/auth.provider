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
 * Every test file vitest collects in a package is compiled by the program
 * that package's vitest typecheck runs tsc on, and that typecheck is on and
 * fails the run on a source error. A test outside that program runs without
 * its types ever being checked: a `@ts-expect-error` or `satisfies` in it
 * proves nothing.
 *
 * For each workspace under `packages/`, everything is asked of vitest itself,
 * from the package's own config: whether typecheck is enabled, whether it
 * ignores source errors, the files it collects, and the tsconfig it names,
 * whose files TypeScript lists. A collected file outside that program fails,
 * naming the package and the file. There is no list of exceptions. The
 * fixtures under `fixtures/testProgram` hold the guard to each refusal.
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

/** The files a tsconfig hands tsc, as absolute paths. */
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

/**
 * What keeps the package's collected test files from being type-checked;
 * empty when nothing does. Everything is read from the package's own vitest
 * config: whether its typecheck runs, whether source errors fail it, and the
 * tsconfig it hands tsc.
 */
async function testProgramFindings(root: string): Promise<string[]> {
	const vitest = await createVitest("test", { root, watch: false });
	try {
		const typecheck = vitest.config.typecheck;
		const findings: string[] = [];
		if (typecheck.enabled !== true) findings.push("typecheck is off");
		if (typecheck.ignoreSourceErrors === true) findings.push("typecheck ignores source errors");
		const specifications = await vitest.globTestSpecifications();
		if (specifications.length === 0) return [...findings, "collects no test file"];
		// tsc runs only in a run that includes a typecheck-collected file.
		if (!specifications.some((specification) => specification.pool === "typescript")) {
			findings.push("typecheck collects no file, so tsc never runs");
		}
		// Unnamed, tsc reads the root's tsconfig.json, as vitest's typecheck does.
		const program = programFiles(resolve(root, typecheck.tsconfig ?? "tsconfig.json"));
		const collected = [...new Set(specifications.map((s) => resolve(s.moduleId)))];
		for (const file of collected.filter((file) => !program.has(file)).sort()) {
			findings.push(`${file.slice(root.length + 1)} is collected but never compiled`);
		}
		return findings;
	} finally {
		await vitest.close();
	}
}

const fixtures = join(fileURLToPath(import.meta.url), "../fixtures/testProgram");

describe("the guard itself", () => {
	it("catches a package whose typecheck is off", async () => {
		expect(await testProgramFindings(join(fixtures, "typecheck-off"))).toContain(
			"typecheck is off",
		);
	});

	it("catches a package whose typecheck ignores source errors", async () => {
		expect(await testProgramFindings(join(fixtures, "source-errors-ignored"))).toContain(
			"typecheck ignores source errors",
		);
	});

	it("reads the program the package's typecheck names, not a file name it assumes", async () => {
		expect(await testProgramFindings(join(fixtures, "points-at-build-config"))).toEqual([
			"src/__tests__/a.probe.mts is collected but never compiled",
		]);
	});
});

describe("every test file vitest collects is in the program its package's typecheck compiles", () => {
	it("finds the packages to check", () => {
		expect(packages).toContain("core");
	});

	it.each(packages)("%s", async (name) => {
		expect(await testProgramFindings(join(packagesDir, name)), `packages/${name}`).toEqual([]);
	});
});
