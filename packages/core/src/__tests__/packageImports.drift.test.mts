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
 * packageImports.drift.test.mts — a package imports only core (#728, its
 * decided B4 and B13; AGENTS.md, "Extension surface: four axes"). In code a
 * package imports `@o3co/auth-provider-core` and no other workspace package;
 * at run time one package depends on another only through a slot whose
 * contract lives in core.
 *
 * What it reads, with TypeScript's parser, in every source under the `src/`
 * of every workspace but the compositions — declaration files included:
 * `import` and `export … from`, value and type-only
 * alike; `import("…")` in a type position and as a call; `require(…)`,
 * `require.resolve(…)` and `import.meta.resolve(…)`; `import … =
 * require(…)`; and `declare module "…"`, which augments a package it must
 * be able to see. A specifier names a workspace package when it is that
 * package's name or one of its subpaths.
 *
 * The rules, each a case below:
 *
 * - **Product code** — a source outside `__tests__/` and not a `*.test.*` or
 *   `*.spec.*` file, which ships — imports no workspace package but core,
 *   beyond the edges that predate the rule (`TOLERATED_EDGES`). The list is
 *   keyed by the importing workspace and the package imported, with every
 *   name imported through the edge, and may only shrink: an edge or a name
 *   not on it fails, and so does an entry whose import is gone. A specifier
 *   the parser cannot read (`import(x)`, `require(x)`) fails too: it could
 *   be anything.
 * - **Tests** compose what they test, as a composition does, and never
 *   ship: a test may import another workspace package, but only one its
 *   package declares (`devDependencies`, or a runtime dependency), so the
 *   install that runs it has it.
 * - **Everything** names a workspace package — its own included — through
 *   its published entry: the package's name or a subpath its `exports`
 *   lists. And no relative
 *   specifier leaves its workspace: another package's source is reached
 *   through its entry or not at all.
 * - **package.json** agrees: a package's runtime dependencies on workspace
 *   packages (`dependencies`, `peerDependencies`, `optionalDependencies`)
 *   other than core are exactly the packages its tolerated edges import.
 * - **The compositions** (`COMPOSITIONS`) assemble every package — that is
 *   their job — and are not read; each entry must still name a workspace, so
 *   the exemption cannot outlive the directory.
 *
 * What it does not follow is left to review: a specifier assembled at run
 * time outside product code; a require function bound under another name
 * (`const req = createRequire(…)`, which core uses for `express` alone), whose
 * calls are not read; a package reached through a symlink or an absolute
 * path; and a file in a workspace outside its `src/`.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/** The one package every other may import. */
const CORE = "@o3co/auth-provider-core";

/**
 * The workspaces that compose the packages, and may import every one of
 * them: their job is to install and wire the packages together.
 */
const COMPOSITIONS: Readonly<Record<string, string>> = {
	"templates/standalone": "the standalone deployment: it installs and wires every package",
	"tools/composition": "the full-set composition test: it boots every module together",
};

/**
 * The imports between packages that predate the rule (#728), keyed
 * `<importing workspace> -> <package imported>`, each with every name
 * imported through it — `type X` for a type-only import. The list may only
 * shrink: nothing may be added to it, and an entry, or a name, whose import
 * is gone fails until it is removed. These are the three edges AGENTS.md
 * names, the federation adapters' one per adapter.
 */
const TOLERATED_EDGES: Readonly<Record<string, readonly string[]>> = {
	// device-grant → oauth: the device authorization endpoint authenticates
	// its client with oauth's middleware.
	"packages/device-grant -> @o3co/auth-provider-oauth": ["createClientAuthMiddleware"],
	// federation-grants → oauth: the grant routes authenticate their client
	// the same way.
	"packages/federation-grants -> @o3co/auth-provider-oauth": ["createClientAuthMiddleware"],
	// The federation adapters → session: each contributes the session
	// package's redirect policy beside its federation, and the OIDC adapter
	// reads its entries with the session package's section reader.
	"packages/federation-apple -> @o3co/auth-provider-session": ["createFederationRedirectPolicy"],
	"packages/federation-github -> @o3co/auth-provider-session": ["createFederationRedirectPolicy"],
	"packages/federation-google -> @o3co/auth-provider-session": ["createFederationRedirectPolicy"],
	"packages/federation-oidc -> @o3co/auth-provider-session": [
		"createFederationRedirectPolicy",
		"extractFederationSection",
	],
};

/** A workspace: its directory, relative to the repository, and its manifest. */
interface Workspace {
	readonly dir: string;
	readonly name: string;
	readonly exports: readonly string[];
	/** `dependencies`, `peerDependencies` and `optionalDependencies`. */
	readonly runtime: ReadonlySet<string>;
	readonly dev: ReadonlySet<string>;
}

/** The directories `pnpm-workspace.yaml` names, `dir/*` expanded to its children that hold a package.json. */
function workspaceDirs(): string[] {
	const text = readFileSync(join(repoRoot, "pnpm-workspace.yaml"), "utf8");
	const block = text.split(/^packages:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
	const globs = [...block.matchAll(/^\s+-\s+["']?([^"'\s]+)["']?\s*$/gm)].map((match) =>
		String(match[1]),
	);
	const dirs: string[] = [];
	for (const glob of globs) {
		if (!glob.endsWith("/*")) {
			dirs.push(glob);
			continue;
		}
		const parent = glob.slice(0, -2);
		for (const entry of readdirSync(join(repoRoot, parent), { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const dir = `${parent}/${entry.name}`;
			try {
				readFileSync(join(repoRoot, dir, "package.json"));
				dirs.push(dir);
			} catch {
				// a directory without a package.json is no workspace
			}
		}
	}
	return dirs.sort();
}

const WORKSPACES: readonly Workspace[] = workspaceDirs().map((dir) => {
	const manifest = JSON.parse(readFileSync(join(repoRoot, dir, "package.json"), "utf8")) as {
		name: string;
		exports?: Record<string, unknown> | string;
		dependencies?: Record<string, string>;
		peerDependencies?: Record<string, string>;
		optionalDependencies?: Record<string, string>;
		devDependencies?: Record<string, string>;
	};
	const exportsField = manifest.exports;
	return {
		dir,
		name: manifest.name,
		exports:
			exportsField === undefined || typeof exportsField === "string"
				? ["."]
				: Object.keys(exportsField),
		runtime: new Set([
			...Object.keys(manifest.dependencies ?? {}),
			...Object.keys(manifest.peerDependencies ?? {}),
			...Object.keys(manifest.optionalDependencies ?? {}),
		]),
		dev: new Set(Object.keys(manifest.devDependencies ?? {})),
	};
});

const BY_NAME = new Map(WORKSPACES.map((workspace) => [workspace.name, workspace]));

/** The workspace package `specifier` names, and the subpath (`.` or `./…`) it names in it. */
function workspaceOf(
	specifier: string,
): { readonly workspace: Workspace; readonly subpath: string } | undefined {
	for (const workspace of WORKSPACES) {
		if (specifier === workspace.name) return { workspace, subpath: "." };
		if (specifier.startsWith(`${workspace.name}/`)) {
			return { workspace, subpath: `.${specifier.slice(workspace.name.length)}` };
		}
	}
	return undefined;
}

/** One reference a source makes to a module. */
interface Reference {
	readonly specifier: string;
	/** What it takes: the names imported, `type X` for a type-only one, or the form (`*`, `import()`, …). */
	readonly names: readonly string[];
	readonly line: number;
}

/** What a scan found in one source. */
interface Scan {
	readonly references: readonly Reference[];
	/** `line: what` for each reference whose specifier the parser cannot read. */
	readonly holes: readonly string[];
}

const typed = (name: string, typeOnly: boolean): string => (typeOnly ? `type ${name}` : name);

/** Scan `text`, a source named `fileName`. */
function scanSource(fileName: string, text: string): Scan {
	const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true);
	const references: Reference[] = [];
	const holes: string[] = [];
	const lineOf = (node: ts.Node): number =>
		source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
	const add = (node: ts.Node, specifier: string, names: readonly string[]): void => {
		references.push({ specifier, names, line: lineOf(node) });
	};
	const hole = (node: ts.Node, what: string): void => {
		holes.push(`${lineOf(node)}: ${what}`);
	};
	/** The names a named-imports or named-exports clause takes. */
	const elementNames = (
		elements: ts.NodeArray<ts.ImportSpecifier | ts.ExportSpecifier>,
		clauseTypeOnly: boolean,
	): string[] =>
		elements.map((element) =>
			typed((element.propertyName ?? element.name).text, clauseTypeOnly || element.isTypeOnly),
		);
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
			const clause = node.importClause;
			const names: string[] = [];
			if (clause === undefined) names.push("(side effect)");
			else {
				if (clause.name !== undefined) names.push(typed("default", clause.isTypeOnly));
				const bindings = clause.namedBindings;
				if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
					names.push(typed("*", clause.isTypeOnly));
				} else if (bindings !== undefined) {
					names.push(...elementNames(bindings.elements, clause.isTypeOnly));
				}
			}
			add(node, node.moduleSpecifier.text, names);
		} else if (
			ts.isExportDeclaration(node) &&
			node.moduleSpecifier !== undefined &&
			ts.isStringLiteral(node.moduleSpecifier)
		) {
			const clause = node.exportClause;
			add(
				node,
				node.moduleSpecifier.text,
				clause === undefined || ts.isNamespaceExport(clause)
					? [typed("*", node.isTypeOnly)]
					: elementNames(clause.elements, node.isTypeOnly),
			);
		} else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) {
			const literal = node.argument.literal;
			if (ts.isStringLiteral(literal)) {
				add(node, literal.text, [
					typed(node.qualifier === undefined ? "*" : node.qualifier.getText(source), true),
				]);
			}
		} else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
			const argument = node.arguments[0];
			if (argument !== undefined && ts.isStringLiteralLike(argument)) {
				add(node, argument.text, ["import()"]);
			} else {
				hole(node, "an import() of a computed specifier");
			}
		} else if (ts.isCallExpression(node) && isRequireLike(node.expression)) {
			const argument = node.arguments[0];
			const form = ts.isIdentifier(node.expression) ? "require()" : "resolve()";
			if (argument !== undefined && ts.isStringLiteralLike(argument)) {
				add(node, argument.text, [form]);
			} else {
				hole(node, `a ${form} of a computed specifier`);
			}
		} else if (
			ts.isImportEqualsDeclaration(node) &&
			ts.isExternalModuleReference(node.moduleReference)
		) {
			const expression = node.moduleReference.expression;
			if (ts.isStringLiteralLike(expression)) add(node, expression.text, ["require()"]);
			else hole(node, "an import-equals require of a computed specifier");
		} else if (ts.isModuleDeclaration(node) && ts.isStringLiteral(node.name)) {
			add(node, node.name.text, ["declare module"]);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return { references, holes };
}

/** `require(…)`, `require.resolve(…)` or `import.meta.resolve(…)`. */
function isRequireLike(callee: ts.Expression): boolean {
	if (ts.isIdentifier(callee)) return callee.text === "require";
	if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "resolve") return false;
	const target = callee.expression;
	return (
		(ts.isIdentifier(target) && target.text === "require") ||
		(ts.isMetaProperty(target) && target.keywordToken === ts.SyntaxKind.ImportKeyword)
	);
}

/**
 * Every source file under `dir`, relative to the repository — declaration
 * files (`.d.ts`, `.d.mts`, `.d.cts`) included: one can import or augment a
 * package as surely as a module can.
 */
function sourcesUnder(dir: string): string[] {
	const files: string[] = [];
	let entries: Dirent[];
	try {
		entries = readdirSync(join(repoRoot, dir), { withFileTypes: true });
	} catch {
		return files;
	}
	for (const entry of entries) {
		if (["node_modules", "dist", "coverage"].includes(entry.name)) continue;
		const path = `${dir}/${entry.name}`;
		if (entry.isDirectory()) files.push(...sourcesUnder(path));
		else if (/\.[cm]?[jt]s$/.test(entry.name)) files.push(path);
	}
	return files;
}

/** Whether `file` is a test: under a `__tests__/` directory, or a `*.test.*` / `*.spec.*` file. */
const isTest = (file: string): boolean =>
	file.split("/").includes("__tests__") || /\.(test|spec)\.[cm]?[jt]s$/.test(file);

/** One reference a workspace's source makes, with where it was found. */
interface Found extends Reference {
	readonly workspace: Workspace;
	readonly file: string;
	readonly test: boolean;
}

const SCANNED: readonly Workspace[] = WORKSPACES.filter(
	(workspace) => !Object.hasOwn(COMPOSITIONS, workspace.dir),
);

const FOUND: Found[] = [];
const HOLES: string[] = [];
for (const workspace of SCANNED) {
	for (const file of sourcesUnder(`${workspace.dir}/src`)) {
		const scan = scanSource(file, readFileSync(join(repoRoot, file), "utf8"));
		const test = isTest(file);
		for (const reference of scan.references) FOUND.push({ ...reference, workspace, file, test });
		if (!test) HOLES.push(...scan.holes.map((hole) => `${file}:${hole}`));
	}
}

/** `<importing workspace> -> <package imported>` */
const edgeKey = (from: Workspace, to: Workspace): string => `${from.dir} -> ${to.name}`;

/** The edges product code makes to a workspace package other than core, each with the names taken, sorted. */
function productEdges(): Map<string, string[]> {
	const edges = new Map<string, Set<string>>();
	for (const found of FOUND) {
		if (found.test) continue;
		const target = workspaceOf(found.specifier)?.workspace;
		if (target === undefined || target.name === CORE || target === found.workspace) continue;
		const key = edgeKey(found.workspace, target);
		const names = edges.get(key) ?? new Set<string>();
		for (const name of found.names) names.add(name);
		edges.set(key, names);
	}
	return new Map([...edges].map(([key, names]) => [key, [...names].sort()]));
}

describe("the package-import scan", () => {
	it("reads value and type-only imports, export-from, namespaces, defaults and side effects", () => {
		const { references, holes } = scanSource(
			"example.mts",
			[
				'import { a, type B, c as d } from "pkg-a";',
				'import type { E } from "pkg-b";',
				'import * as ns from "pkg-c";',
				'import def from "pkg-d";',
				'import "pkg-e";',
				'export { f, type G } from "pkg-f";',
				'export * from "pkg-g";',
				'export type * as H from "pkg-h";',
			].join("\n"),
		);
		expect(references.map(({ specifier, names }) => [specifier, names])).toEqual([
			["pkg-a", ["a", "type B", "c"]],
			["pkg-b", ["type E"]],
			["pkg-c", ["*"]],
			["pkg-d", ["default"]],
			["pkg-e", ["(side effect)"]],
			["pkg-f", ["f", "type G"]],
			["pkg-g", ["*"]],
			["pkg-h", ["type *"]],
		]);
		expect(holes).toEqual([]);
	});

	it("reads import() as a call and as a type, require, require.resolve, import.meta.resolve, import-equals and declare module", () => {
		const { references, holes } = scanSource(
			"example.mts",
			[
				'const lazy = await import("pkg-a");',
				'type T = import("pkg-b").Thing;',
				'const req = require("pkg-c");',
				'const path = require.resolve("pkg-d/reference.conf");',
				'const url = import.meta.resolve("pkg-e");',
				'import legacy = require("pkg-f");',
				'declare module "pkg-g" { interface Map { readonly x?: number } }',
			].join("\n"),
		);
		expect(references.map(({ specifier, names }) => [specifier, names])).toEqual([
			["pkg-a", ["import()"]],
			["pkg-b", ["type Thing"]],
			["pkg-c", ["require()"]],
			["pkg-d/reference.conf", ["resolve()"]],
			["pkg-e", ["resolve()"]],
			["pkg-f", ["require()"]],
			["pkg-g", ["declare module"]],
		]);
		expect(holes).toEqual([]);
	});

	it("reports a specifier it cannot read, by line", () => {
		const { holes } = scanSource(
			"example.mts",
			[
				"const a = await import(name);",
				"const b = require(name);",
				"const c = require.resolve(name);",
			].join("\n"),
		);
		expect(holes).toEqual([
			"1: an import() of a computed specifier",
			"2: a require() of a computed specifier",
			"3: a resolve() of a computed specifier",
		]);
	});

	it("names a workspace package by its name or a subpath of it, and nothing else", () => {
		expect(workspaceOf(CORE)?.subpath).toBe(".");
		expect(workspaceOf(`${CORE}/testing`)?.subpath).toBe("./testing");
		expect(workspaceOf(`${CORE}-extra`)).toBeUndefined();
		expect(workspaceOf("zod")).toBeUndefined();
	});

	it("walks a plausible workspace (the guard is not vacuous)", () => {
		expect(SCANNED.some((workspace) => workspace.name === CORE)).toBe(true);
		expect(SCANNED.length).toBeGreaterThan(10);
		expect(FOUND.filter((found) => !found.test).length).toBeGreaterThan(500);
	});
});

describe("a package imports only core (#728)", () => {
	it("exempts only compositions that are workspaces", () => {
		const dirs = new Set(WORKSPACES.map((workspace) => workspace.dir));
		expect(Object.keys(COMPOSITIONS).filter((dir) => !dirs.has(dir))).toEqual([]);
	});

	it("finds no import between packages in product code beyond the tolerated edges, and no name beyond the ones each lists", () => {
		const untolerated = [...productEdges()].flatMap(([key, names]) => {
			const tolerated = TOLERATED_EDGES[key];
			if (tolerated === undefined) return [`${key}: ${names.join(", ")}`];
			const extra = names.filter((name) => !tolerated.includes(name));
			return extra.length === 0 ? [] : [`${key}: ${extra.join(", ")} (not tolerated)`];
		});
		expect(
			untolerated,
			"an import between packages: reach the other package through a slot core declares",
		).toEqual([]);
	});

	it("keeps no tolerated edge, or name, whose import is gone: the list only shrinks", () => {
		const edges = productEdges();
		const stale = Object.entries(TOLERATED_EDGES).flatMap(([key, names]) => {
			const found = edges.get(key);
			if (found === undefined) return [`${key}: the edge is gone`];
			const gone = names.filter((name) => !found.includes(name));
			return gone.length === 0 ? [] : [`${key}: ${gone.join(", ")} no longer imported`];
		});
		expect(stale, "remove it from TOLERATED_EDGES").toEqual([]);
	});

	it("reads every specifier in product code", () => {
		expect(HOLES).toEqual([]);
	});

	it("names a workspace package only through its published entry, its own included", () => {
		const unpublished = FOUND.flatMap((found) => {
			const named = workspaceOf(found.specifier);
			if (named === undefined) return [];
			return named.workspace.exports.includes(named.subpath)
				? []
				: [`${found.file}:${found.line}: ${found.specifier}`];
		});
		expect(unpublished).toEqual([]);
	});

	it("reaches no file outside its workspace by a relative specifier", () => {
		const escaping = FOUND.flatMap((found) => {
			if (!found.specifier.startsWith(".")) return [];
			const target = posix.normalize(posix.join(posix.dirname(found.file), found.specifier));
			return target.startsWith(`${found.workspace.dir}/`)
				? []
				: [`${found.file}:${found.line}: ${found.specifier}`];
		});
		expect(escaping).toEqual([]);
	});

	it("lets a test import another package only when its package declares it", () => {
		const undeclared = FOUND.flatMap((found) => {
			if (!found.test) return [];
			const target = workspaceOf(found.specifier)?.workspace;
			if (target === undefined || target === found.workspace) return [];
			return found.workspace.dev.has(target.name) || found.workspace.runtime.has(target.name)
				? []
				: [`${found.file}:${found.line}: ${target.name}`];
		});
		expect(undeclared).toEqual([]);
	});

	it("declares, as a package's runtime dependencies on other workspace packages, exactly what its tolerated edges import", () => {
		const declared = SCANNED.flatMap((workspace) =>
			[...workspace.runtime]
				.filter((name) => BY_NAME.has(name) && name !== CORE && name !== workspace.name)
				.map((name) => `${workspace.dir} -> ${name}`),
		).sort();
		const tolerated = Object.keys(TOLERATED_EDGES).sort();
		expect(declared).toEqual(tolerated);
	});
});
