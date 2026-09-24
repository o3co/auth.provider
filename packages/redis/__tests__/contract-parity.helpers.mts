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

// What the contract parity tests read from a suite file, by its syntax tree
// rather than its lines (#626).
//
// Read line by line, a prologue check accepts any line that starts with
// `import ` — so `import { it as rawIt } from "vitest"; const it = rawIt.skip;`
// on one line passes it and skips every case. And a caller found by string
// search is still found when the call is commented out. The tree has neither
// problem: a declaration is a statement whatever line it shares, and a
// comment is not a call.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";

const parse = (path: string): ts.SourceFile =>
	ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);

/**
 * Every top-level statement that starts before `bodyStart` (a character
 * offset) and is not an import declaration: what may not be above a suite's
 * body. Comments are not statements, so they are allowed without a rule.
 */
export const prologueDeclarations = (path: string, bodyStart: number): string[] =>
	parse(path)
		.statements.filter((statement) => statement.getStart() < bodyStart)
		.filter((statement) => !ts.isImportDeclaration(statement))
		.map((statement) => statement.getText().split("\n")[0] ?? "");

/**
 * The module specifiers of the import declarations above `bodyStart`, however
 * quoted, side-effect imports included.
 */
export const prologueImports = (path: string, bodyStart: number): string[] =>
	parse(path)
		.statements.filter((statement) => statement.getStart() < bodyStart)
		.filter(ts.isImportDeclaration)
		.map((statement) => (statement.moduleSpecifier as ts.StringLiteral).text);

/**
 * Whether an import specifier names a package — `vitest`,
 * `@o3co/auth-provider-core`, `node:fs` — rather than a location. A relative,
 * absolute, `file:` or drive-letter path, or core's `#/` alias, is a location:
 * it reaches into core's source instead of what the package publishes.
 */
export const isPackageSpecifier = (specifier: string): boolean =>
	specifier.startsWith("node:") ||
	/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(\/[\w.-]+)*$/i.test(specifier);

/**
 * The `.test.mts` files in `dir` that call `runner(…)` — a call, not a
 * mention. It does not judge whether the call runs: one inside a
 * `describe.skip` still counts.
 */
export const callersOf = (dir: string, runner: string): string[] =>
	readdirSync(dir)
		.filter((name) => name.endsWith(".test.mts"))
		.filter((name) => {
			let calls = false;
			const visit = (node: ts.Node): void => {
				if (
					ts.isCallExpression(node) &&
					ts.isIdentifier(node.expression) &&
					node.expression.text === runner
				) {
					calls = true;
					return;
				}
				ts.forEachChild(node, visit);
			};
			visit(parse(join(dir, name)));
			return calls;
		});
