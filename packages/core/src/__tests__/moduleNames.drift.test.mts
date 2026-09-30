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
 * Every module this repository ships is named in kebab-case,
 * `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, so a configuration section can be named
 * after the module verbatim.
 *
 * Read with TypeScript's parser: every `defineModule({ name })` call in the
 * product sources (outside `__tests__/`, not a `*.test.*` or `*.spec.*` file)
 * of every workspace's `src/`, the standalone template and `tools/` included.
 * A name is a string literal; a `const` in the same file initialised with
 * one; or a template literal whose static parts must form a kebab-case name
 * with each substitution read as one kebab-case word
 * (`federation-oidc-${name}`, named per federation). Any other name cannot be
 * read, and fails as a name that is not kebab-case would.
 *
 * Boot does not refuse a name that is not kebab-case, so an out-of-tree
 * module named otherwise still boots; this holds the repository's own modules
 * alone. Test fixtures are not read: they never reach a deployment.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/** A module name a configuration section can carry verbatim. */
const KEBAB_CASE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

/** What a substitution in a template-literal name is read as: one kebab-case word. */
const SUBSTITUTION = "x";

/** One `defineModule` call's name, as the scan read it. */
interface ModuleName {
	readonly file: string;
	readonly line: number;
	/** The name, a substitution read as `x`; `undefined` when the scan cannot read it. */
	readonly name: string | undefined;
	/** The source text of the name, for the message. */
	readonly text: string;
}

/** The names of the `defineModule({ … })` calls in `text`, a source named `file`. */
function moduleNames(file: string, text: string): ModuleName[] {
	const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
	const constants = new Map<string, string>();
	const collect = (node: ts.Node): void => {
		if (
			ts.isVariableDeclaration(node) &&
			ts.isIdentifier(node.name) &&
			node.initializer !== undefined &&
			ts.isStringLiteralLike(node.initializer) &&
			ts.isVariableDeclarationList(node.parent) &&
			(node.parent.flags & ts.NodeFlags.Const) !== 0
		) {
			constants.set(node.name.text, node.initializer.text);
		}
		ts.forEachChild(node, collect);
	};
	collect(source);
	const read = (expression: ts.Expression): string | undefined => {
		if (ts.isStringLiteralLike(expression)) return expression.text;
		if (ts.isIdentifier(expression)) return constants.get(expression.text);
		if (ts.isTemplateExpression(expression)) {
			return (
				expression.head.text +
				expression.templateSpans.map((span) => SUBSTITUTION + span.literal.text).join("")
			);
		}
		return undefined;
	};
	const found: ModuleName[] = [];
	const visit = (node: ts.Node): void => {
		if (
			ts.isCallExpression(node) &&
			((ts.isIdentifier(node.expression) && node.expression.text === "defineModule") ||
				(ts.isPropertyAccessExpression(node.expression) &&
					node.expression.name.text === "defineModule"))
		) {
			const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
			const argument = node.arguments[0];
			const property =
				argument !== undefined && ts.isObjectLiteralExpression(argument)
					? argument.properties.find(
							(candidate): candidate is ts.PropertyAssignment =>
								ts.isPropertyAssignment(candidate) &&
								ts.isIdentifier(candidate.name) &&
								candidate.name.text === "name",
						)
					: undefined;
			found.push({
				file,
				line,
				name: property === undefined ? undefined : read(property.initializer),
				text:
					property === undefined
						? "(no name the scan can read)"
						: property.initializer.getText(source),
			});
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return found;
}

/** Whether `file` is a test: under a `__tests__/` directory, or a `*.test.*` / `*.spec.*` file. */
const isTest = (file: string): boolean =>
	file.split("/").includes("__tests__") || /\.(test|spec)\.[cm]?[jt]s$/.test(file);

/** Every product source under `dir`, relative to the repository. */
function productSources(dir: string): string[] {
	const files: string[] = [];
	let entries: Dirent[];
	try {
		entries = readdirSync(join(repoRoot, dir), { withFileTypes: true });
	} catch {
		return files;
	}
	for (const entry of entries) {
		if (["node_modules", "dist", "coverage", "__tests__"].includes(entry.name)) continue;
		const path = `${dir}/${entry.name}`;
		if (entry.isDirectory()) files.push(...productSources(path));
		else if (
			/\.[cm]?[jt]s$/.test(entry.name) &&
			!/\.d\.[cm]?ts$/.test(entry.name) &&
			!isTest(path)
		) {
			files.push(path);
		}
	}
	return files;
}

/** Every workspace's `src/`: the packages, the templates, the tools and create-app. */
const SOURCE_ROOTS: readonly string[] = [
	...["packages", "templates", "tools"].flatMap((parent) =>
		readdirSync(join(repoRoot, parent), { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map((entry) => `${parent}/${entry.name}/src`),
	),
	"create-app/src",
];

const NAMES: readonly ModuleName[] = SOURCE_ROOTS.flatMap(productSources).flatMap((file) =>
	moduleNames(file, readFileSync(join(repoRoot, file), "utf8")),
);

describe("the module-name scan", () => {
	it("reads a string literal, a const of one, and a template literal with each substitution as one word", () => {
		const names = moduleNames(
			"example.mts",
			[
				'const NAME = "named-by-const";',
				'defineModule({ name: "a-literal" });',
				"defineModule({ name: NAME });",
				// biome-ignore lint/suspicious/noTemplateCurlyInString: the source under test
				"defineModule({ name: `federation-oidc-${name}` });",
				"core.defineModule({ name: 'from-a-namespace' });",
				"defineModule({ name: computeName() });",
				"defineModule(spec);",
			].join("\n"),
		);
		expect(names.map(({ name }) => name)).toEqual([
			"a-literal",
			"named-by-const",
			"federation-oidc-x",
			"from-a-namespace",
			undefined,
			undefined,
		]);
	});

	it("holds kebab-case to lower-case words of letters and digits joined by single hyphens", () => {
		for (const name of ["session", "core-session-stores-memory", "redis-clients", "a1-b2"]) {
			expect(KEBAB_CASE.test(name), name).toBe(true);
		}
		for (const name of [
			"sessionStoreModule",
			"federation:google",
			"standalone:key-store",
			"-leading",
			"trailing-",
			"double--hyphen",
			"under_score",
			"1starts-with-a-digit",
			"",
		]) {
			expect(KEBAB_CASE.test(name), name).toBe(false);
		}
	});

	it("walks a plausible repository (the guard is not vacuous)", () => {
		expect(NAMES.length).toBeGreaterThan(50);
		expect(NAMES.some((found) => found.file.startsWith("templates/standalone/src/"))).toBe(true);
	});
});

describe("no module the repository ships is named after a reserved section", () => {
	it("names none adapters, the composition root's own section, nor core", () => {
		const reserved = NAMES.filter(
			(found) => found.name === "adapters" || found.name === "core",
		).map((found) => `${found.file}:${found.line}: ${found.text}`);
		expect(reserved).toEqual([]);
	});
});

describe("every module the repository ships is named in kebab-case", () => {
	it("names each one in kebab-case, in a form the scan can read", () => {
		const offenders = NAMES.filter(
			(found) => found.name === undefined || !KEBAB_CASE.test(found.name),
		).map((found) => `${found.file}:${found.line}: ${found.text}`);
		expect(offenders).toEqual([]);
	});
});
