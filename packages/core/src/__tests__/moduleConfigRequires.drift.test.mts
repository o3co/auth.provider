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
 * No manifest outside core requires `config`. A module reads its own section
 * (`deps.section`) and what another module owns through a slot whose contract
 * is core's; the whole configuration is core's to parse. The manifests that
 * still list `config` are in {@link CONFIG_REQUIRERS}, and the list may only
 * shrink: a manifest that lists it and is not listed fails, and so does a
 * listed one that no longer does.
 *
 * Read with TypeScript's parser and binder, in the product code of every
 * workspace but core (a source under `src/` outside `__tests__/` that is not
 * a `*.test.*` or `*.spec.*` file): every `defineModule(…)` call, and every
 * other object literal with a `name` and a `requires` or an `optional` that
 * is a list (an array literal, or a `const` bound to one). The workspaces are
 * `pnpm-workspace.yaml`'s: `dir/*` and a package's own path; any other
 * pattern refuses the scan rather than letting it walk nothing. A manifest
 * lists `config` when its `requires` or its `optional` does: a factory is
 * handed it either way.
 *
 * The manifest is the call's argument, an object literal or a `const` bound
 * to one. A key is read as it is spelled (`requires`, `"requires"`,
 * `["requires"]`), the last one written wins, and a shorthand is read through
 * the binding it names. A list is an array literal of string literals,
 * through `as const` and through the `const` in scope where it is used;
 * `name` is a string literal or a `const` bound to one, likewise. Anything
 * else is reported and fails: a manifest that is not an object literal; a
 * list that is a `let`, a parameter, an import, a call or a spread; a list a
 * spread may supply (`spreadMayWrite`) or a computed key may name; and a
 * manifest listing `config` whose `name` cannot be read, since the list is
 * keyed by it.
 *
 * Not seen, left to review: `config` a manifest built by a factory captures
 * through the closure (`oauthModule({ config })`) without listing it.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/**
 * The manifests outside core that require `config`, keyed
 * `<workspace> -> <module name>`. The list may only shrink: each entry leaves
 * as its module reads its own section and the slots it needs instead.
 */
const CONFIG_REQUIRERS: readonly string[] = [
	// Each reads a section of its own that is not yet under its name, and some
	// a key of another module's section beside it.
	"packages/federation-grants -> federation-grants",
	"packages/oauth -> oauth",
	"packages/oauth -> oauth-authorization",
	"packages/oauth -> oauth-session",
	"packages/oauth -> subject-revocation-service",
	"packages/session -> session",
	"packages/webauthn -> webauthn",
	// The standalone template's deprecated `stores` bundle.
	"templates/standalone -> stores",
];

/** Whether `dir` under `root` holds a package.json. */
const isPackage = (root: string, dir: string): boolean => {
	try {
		readFileSync(join(root, dir, "package.json"));
		return true;
	} catch {
		return false;
	}
};

/**
 * The workspaces a `pnpm-workspace.yaml` (its text) names, under `root`:
 * each `dir/*` expanded to the children of `dir` that hold a package.json,
 * and each bare path kept when it holds one. Any other pattern — `**`, a
 * negation, another glob, a path holding no package — is refused, naming
 * it, as is a file that names no workspace: the scan would walk nothing
 * under it and pass.
 */
function workspaceDirsIn(text: string, root: string): string[] {
	const block = text.split(/^packages:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
	const patterns = [...block.matchAll(/^\s+-\s+["']?([^"'\s]+)["']?\s*$/gm)].map((match) =>
		String(match[1]),
	);
	if (patterns.length === 0) {
		throw new Error("pnpm-workspace.yaml names no workspace under packages:");
	}
	const refuse = (pattern: string, why: string): never => {
		throw new Error(
			`pnpm-workspace.yaml names ${JSON.stringify(pattern)}, ${why}: the config-requires scan would walk nothing under it and pass`,
		);
	};
	const dirs: string[] = [];
	for (const pattern of patterns) {
		const parent = pattern.endsWith("/*") ? pattern.slice(0, -2) : pattern;
		if (/[*?[\]{}!]/.test(parent)) {
			refuse(pattern, "a pattern the scan does not expand (only dir/* and a package's path)");
		}
		if (parent === pattern) {
			if (!isPackage(root, pattern)) refuse(pattern, "a path that holds no package.json");
			dirs.push(pattern);
			continue;
		}
		for (const entry of readdirSync(join(root, parent), { withFileTypes: true })) {
			const dir = `${parent}/${entry.name}`;
			// A directory without a package.json is no workspace.
			if (entry.isDirectory() && isPackage(root, dir)) dirs.push(dir);
		}
	}
	return dirs.sort();
}

/** The workspaces this repository's `pnpm-workspace.yaml` names. */
const workspaceDirs = (): string[] =>
	workspaceDirsIn(readFileSync(join(repoRoot, "pnpm-workspace.yaml"), "utf8"), repoRoot);

/** Whether `file` is a test: under a `__tests__/` directory, or a `*.test.*` / `*.spec.*` file. */
const isTest = (file: string): boolean =>
	file.split("/").includes("__tests__") || /\.(test|spec)\.[cm]?[jt]s$/.test(file);

/** Every product source under `dir`, relative to the repository. */
function productSourcesUnder(dir: string): string[] {
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
		if (entry.isDirectory()) files.push(...productSourcesUnder(path));
		else if (/\.[cm]?[jt]s$/.test(entry.name) && !entry.name.endsWith(".d.mts") && !isTest(path)) {
			files.push(path);
		}
	}
	return files;
}

/** One manifest found: where, its name (`undefined` when it cannot be read), and what it lists. */
interface Manifest {
	readonly line: number;
	readonly name: string | undefined;
	/** `[]` when absent; `undefined` when it cannot be read as an array of string literals. */
	readonly requires: readonly string[] | undefined;
	/** `[]` when absent; `undefined` when it cannot be read as an array of string literals. */
	readonly optional: readonly string[] | undefined;
}

/** Whether a manifest lists `config`, in its `requires` or its `optional`. */
const readsConfig = (manifest: Manifest): boolean =>
	manifest.requires?.includes("config") === true || manifest.optional?.includes("config") === true;

/**
 * What a key of an object literal holds, as JavaScript would settle it: the
 * last write wins. `absent` when nothing writes it; `unknown` when a spread
 * or a computed key after the last write may.
 */
type Slot =
	| { readonly kind: "absent" }
	| { readonly kind: "unknown" }
	| { readonly kind: "written"; readonly property: ts.ObjectLiteralElementLike };

/** A program over `source` alone, for its binder: which declaration an identifier names. */
function checkerFor(source: ts.SourceFile): ts.TypeChecker {
	const host: ts.CompilerHost = {
		getSourceFile: (fileName) => (fileName === source.fileName ? source : undefined),
		writeFile: () => {},
		getDefaultLibFileName: () => "lib.d.ts",
		useCaseSensitiveFileNames: () => true,
		getCanonicalFileName: (fileName) => fileName,
		getCurrentDirectory: () => "",
		getNewLine: () => "\n",
		fileExists: (fileName) => fileName === source.fileName,
		readFile: () => undefined,
	};
	return ts
		.createProgram({
			rootNames: [source.fileName],
			options: { noLib: true, noResolve: true, allowJs: true, types: [] },
			host,
		})
		.getTypeChecker();
}

/** The manifests in `text`, a source named `fileName`. */
function manifestsIn(fileName: string, text: string): Manifest[] {
	// A source that names neither holds no manifest, and is spared a program.
	if (!text.includes("defineModule") && !/\b(requires|optional)\b/.test(text)) return [];
	const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true);
	const checker = checkerFor(source);

	/** The initializer of the `const` a symbol is, or `undefined` for any other binding. */
	const constInitializer = (symbol: ts.Symbol | undefined): ts.Expression | undefined => {
		const declaration = symbol?.valueDeclaration;
		if (
			declaration === undefined ||
			!ts.isVariableDeclaration(declaration) ||
			!ts.isIdentifier(declaration.name) ||
			declaration.initializer === undefined ||
			!ts.isVariableDeclarationList(declaration.parent) ||
			(declaration.parent.flags & ts.NodeFlags.Const) === 0
		) {
			return undefined;
		}
		return declaration.initializer;
	};

	/** The expression under `as`, `satisfies`, `!` and parentheses, and behind the `const` in scope. */
	const unwrap = (
		expression: ts.Expression,
		seen: ReadonlySet<ts.Node> = new Set(),
	): ts.Expression => {
		let current = expression;
		while (
			ts.isAsExpression(current) ||
			ts.isSatisfiesExpression(current) ||
			ts.isNonNullExpression(current) ||
			ts.isParenthesizedExpression(current)
		) {
			current = current.expression;
		}
		if (ts.isIdentifier(current)) {
			const bound = constInitializer(checker.getSymbolAtLocation(current));
			if (bound !== undefined && !seen.has(bound)) return unwrap(bound, new Set([...seen, bound]));
		}
		return current;
	};

	/** The key a property is written under, or `undefined` when it is computed from anything but a literal. */
	const keyOf = (property: ts.ObjectLiteralElementLike): string | undefined => {
		const name = property.name;
		if (name === undefined) return undefined;
		if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
			return name.text;
		}
		if (ts.isComputedPropertyName(name)) {
			const expression = unwrap(name.expression);
			return ts.isStringLiteralLike(expression) ? expression.text : undefined;
		}
		return undefined;
	};

	/**
	 * Whether a spread may write `key`: not when it is an object literal that
	 * does not — or a conditional whose branches are such literals, as in
	 * `...(x === undefined ? {} : { x })` — and otherwise, it may.
	 */
	const spreadMayWrite = (expression: ts.Expression, key: string): boolean => {
		const spread = unwrap(expression);
		if (ts.isObjectLiteralExpression(spread)) return slotOf(spread, key).kind !== "absent";
		if (ts.isConditionalExpression(spread)) {
			return spreadMayWrite(spread.whenTrue, key) || spreadMayWrite(spread.whenFalse, key);
		}
		return true;
	};

	/** What `key` holds in `object` once every property is applied, in order. */
	const slotOf = (object: ts.ObjectLiteralExpression, key: string): Slot => {
		let slot: Slot = { kind: "absent" };
		for (const property of object.properties) {
			if (ts.isSpreadAssignment(property)) {
				if (spreadMayWrite(property.expression, key)) slot = { kind: "unknown" };
				continue;
			}
			const written = keyOf(property);
			if (written === undefined) slot = { kind: "unknown" };
			else if (written === key) slot = { kind: "written", property };
		}
		return slot;
	};

	/** The value a written property holds: its initializer, or what a shorthand names. */
	const writtenValue = (property: ts.ObjectLiteralElementLike): ts.Expression | undefined => {
		if (ts.isPropertyAssignment(property)) return unwrap(property.initializer);
		if (ts.isShorthandPropertyAssignment(property)) {
			const bound = constInitializer(checker.getShorthandAssignmentValueSymbol(property));
			return bound === undefined ? undefined : unwrap(bound);
		}
		return undefined;
	};

	/** A list of keys: `[]` when absent, `undefined` when it cannot be read. */
	const listOf = (
		object: ts.ObjectLiteralExpression,
		key: string,
	): readonly string[] | undefined => {
		const slot = slotOf(object, key);
		if (slot.kind === "absent") return [];
		if (slot.kind === "unknown") return undefined;
		const value = writtenValue(slot.property);
		if (value === undefined || !ts.isArrayLiteralExpression(value)) return undefined;
		const keys: string[] = [];
		for (const element of value.elements) {
			if (!ts.isStringLiteralLike(element)) return undefined;
			keys.push(element.text);
		}
		return keys;
	};

	/** The name: a string literal, or a `const` bound to one; `undefined` otherwise. */
	const nameOf = (object: ts.ObjectLiteralExpression): string | undefined => {
		const slot = slotOf(object, "name");
		if (slot.kind !== "written") return undefined;
		const value = writtenValue(slot.property);
		return value !== undefined && ts.isStringLiteralLike(value) ? value.text : undefined;
	};

	const lineOf = (node: ts.Node): number =>
		source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;

	const isDefineModuleCall = (node: ts.Node): node is ts.CallExpression =>
		ts.isCallExpression(node) &&
		((ts.isIdentifier(node.expression) && node.expression.text === "defineModule") ||
			(ts.isPropertyAccessExpression(node.expression) &&
				node.expression.name.text === "defineModule"));

	const read = (line: number, object: ts.ObjectLiteralExpression): Manifest => ({
		line,
		name: nameOf(object),
		requires: listOf(object, "requires"),
		optional: listOf(object, "optional"),
	});

	// Each defineModule call's manifest, then any other object literal shaped
	// like one. A literal read as a call's manifest is not read again.
	const found: { readonly position: number; readonly manifest: Manifest }[] = [];
	const consumed = new Set<ts.Node>();
	const calls = (node: ts.Node): void => {
		if (isDefineModuleCall(node)) {
			const argument = node.arguments[0];
			const manifest = argument === undefined ? undefined : unwrap(argument);
			const line = lineOf(node);
			if (manifest !== undefined && ts.isObjectLiteralExpression(manifest)) {
				consumed.add(manifest);
				found.push({ position: node.getStart(source), manifest: read(line, manifest) });
			} else {
				found.push({
					position: node.getStart(source),
					manifest: { line, name: undefined, requires: undefined, optional: undefined },
				});
			}
		}
		ts.forEachChild(node, calls);
	};
	calls(source);
	/** Whether `key` is written with a list: an array literal, or a const bound to one. */
	const writesList = (object: ts.ObjectLiteralExpression, key: string): boolean => {
		const slot = slotOf(object, key);
		if (slot.kind !== "written") return false;
		const value = writtenValue(slot.property);
		return value !== undefined && ts.isArrayLiteralExpression(value);
	};
	const literals = (node: ts.Node): void => {
		if (
			ts.isObjectLiteralExpression(node) &&
			!consumed.has(node) &&
			slotOf(node, "name").kind === "written" &&
			(writesList(node, "requires") || writesList(node, "optional"))
		) {
			found.push({ position: node.getStart(source), manifest: read(lineOf(node), node) });
		}
		ts.forEachChild(node, literals);
	};
	literals(source);
	return found.sort((x, y) => x.position - y.position).map(({ manifest }) => manifest);
}

/** Every manifest in the product code of every workspace but core, with its workspace and file. */
const FOUND = workspaceDirs()
	.filter((dir) => dir !== "packages/core")
	.flatMap((dir) =>
		productSourcesUnder(`${dir}/src`).flatMap((file) =>
			manifestsIn(file, readFileSync(join(repoRoot, file), "utf8")).map((manifest) => ({
				...manifest,
				workspace: dir,
				file,
			})),
		),
	);

describe("the manifest scan", () => {
	it("reads requires as an array literal, through as const and a const of the file, and a name through a const", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'const NAME = "b";',
				'const REQUIRES = ["config", "keyStore"] as const;',
				'defineModule({ name: "a", requires: ["config"] });',
				"defineModule({ name: NAME, requires: REQUIRES });",
				'defineModule({ name: "c", requires: ["keyStore"] as const });',
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([
			["a", ["config"]],
			["b", ["config", "keyStore"]],
			["c", ["keyStore"]],
		]);
	});

	it("reports a requires or a name it cannot read", () => {
		const found = manifestsIn(
			"example.mts",
			[
				"defineModule({ name: prefix + n, requires: [...base, 'config'] });",
				'defineModule({ name: "y", requires: build() });',
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([
			[undefined, undefined],
			["y", undefined],
		]);
	});

	it("reads a shorthand property through the const it names", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'const name = "s";',
				'const requires = ["config"] as const;',
				"defineModule({ name, requires });",
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([["s", ["config"]]]);
	});

	it("reads a quoted key as the key it spells", () => {
		const found = manifestsIn(
			"example.mts",
			'defineModule({ "name": "q", "requires": ["config"], ["optional"]: ["logger"] });',
		);
		expect(found.map(({ name, requires, optional }) => [name, requires, optional])).toEqual([
			["q", ["config"], ["logger"]],
		]);
	});

	it("reads optional beside requires, and a manifest that lists either", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'defineModule({ name: "o", optional: ["config"] });',
				'defineModule({ name: "r", requires: ["keyStore"] });',
				'defineModule({ name: "n" });',
			].join("\n"),
		);
		expect(found.map(({ name, requires, optional }) => [name, requires, optional])).toEqual([
			["o", [], ["config"]],
			["r", ["keyStore"], []],
			["n", [], []],
		]);
	});

	it("resolves a const in the scope it is used in, not the file's last of that name", () => {
		// A file-wide table would read the last `REQUIRES` for both and miss
		// `a`'s config; and a parameter that shadows a const is no const.
		const found = manifestsIn(
			"example.mts",
			[
				"function a() {",
				'\tconst REQUIRES = ["config"] as const;',
				'\treturn defineModule({ name: "a", requires: REQUIRES });',
				"}",
				"function b() {",
				'\tconst REQUIRES = ["keyStore"] as const;',
				'\treturn defineModule({ name: "b", requires: REQUIRES });',
				"}",
				'const OUTER = ["keyStore"] as const;',
				"function c(OUTER: readonly string[]) {",
				'\treturn defineModule({ name: "c", requires: OUTER });',
				"}",
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([
			["a", ["config"]],
			["b", ["keyStore"]],
			["c", undefined],
		]);
	});

	it("reads no binding but a const: a let, a parameter and an import are not read", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'import { IMPORTED } from "./elsewhere.mjs";',
				'let LET = ["config"];',
				'defineModule({ name: "l", requires: LET });',
				'defineModule({ name: "i", requires: IMPORTED });',
				'const build = (PARAM: string[]) => defineModule({ name: "p", optional: PARAM });',
			].join("\n"),
		);
		expect(found.map(({ name, requires, optional }) => [name, requires, optional])).toEqual([
			["l", undefined, []],
			["i", undefined, []],
			["p", [], undefined],
		]);
	});

	it("reads each defineModule call, and reports the ones whose manifest it cannot read", () => {
		// Anchored on the call, as the module-name scan is: a manifest that is
		// not an object literal, or that a spread may add a list to, is
		// reported rather than passed over.
		const found = manifestsIn(
			"example.mts",
			[
				'const SPEC = { name: "by-const", requires: ["config"] };',
				"defineModule(SPEC);",
				"defineModule(spec);",
				'defineModule({ ...base, name: "spread" });',
				'defineModule({ ...base, name: "spread-then-lists", requires: [], optional: [] });',
				'defineModule({ name: "spread-of-other-keys", requires: ["config"], ...(x ? {} : { x }) });',
				'defineModule({ name: "spread-of-a-list", requires: [], ...(x ? {} : { requires: [] }) });',
				'core.defineModule<R, O>({ name: "namespaced", requires: ["config"] });',
			].join("\n"),
		);
		expect(found.map(({ name, requires, optional }) => [name, requires, optional])).toEqual([
			["by-const", ["config"], []],
			[undefined, undefined, undefined],
			["spread", undefined, undefined],
			["spread-then-lists", [], []],
			["spread-of-other-keys", ["config"], []],
			["spread-of-a-list", undefined, []],
			["namespaced", ["config"], []],
		]);
	});

	it("counts config listed in either requires or optional: deps carry it either way", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'defineModule({ name: "required", requires: ["config"] });',
				'defineModule({ name: "optional", optional: ["config"] });',
				'defineModule({ name: "neither", requires: ["keyStore"], optional: ["logger"] });',
			].join("\n"),
		);
		expect(found.filter(readsConfig).map(({ name }) => name)).toEqual(["required", "optional"]);
	});

	it("takes a literal outside a defineModule call as a manifest only when it lists requires or optional", () => {
		// A literal with a `name` and a flag called `optional` is no manifest;
		// one whose `requires` or `optional` is a list, written or through a
		// const, is.
		const found = manifestsIn(
			"example.mts",
			[
				'const flags = { name: "x", optional: true };',
				'const described = { name: "y", requires: "config" };',
				'const computed = { name: "w", requires: build() };',
				'const REQUIRES = ["config"] as const;',
				'const bound = { name: "b", requires: REQUIRES };',
				'const listed = { name: "l", optional: ["config"] };',
				'const mixed = { name: "m", requires: [dynamic] };',
			].join("\n"),
		);
		expect(found.map(({ name, requires, optional }) => [name, requires, optional])).toEqual([
			["b", ["config"], []],
			["l", [], ["config"]],
			["m", undefined, []],
		]);
	});

	it("walks a plausible workspace (the guard is not vacuous)", () => {
		expect(FOUND.length).toBeGreaterThan(20);
		expect(FOUND.some((manifest) => manifest.name === "oauth")).toBe(true);
	});
});

describe("the workspaces it walks", () => {
	const yaml = (...patterns: string[]) =>
		`packages:\n${patterns.map((pattern) => `  - "${pattern}"\n`).join("")}\nother: 1\n`;

	it("expands dir/* to the packages under it, and keeps a bare path that is a package", () => {
		const dirs = workspaceDirsIn(yaml("packages/*", "create-app"), repoRoot);
		expect(dirs).toContain("packages/oauth");
		expect(dirs).toContain("create-app");
		expect(dirs).not.toContain("packages");
	});

	it("refuses a pattern it cannot expand, rather than walking nothing under it and passing", () => {
		for (const pattern of [
			"packages/**",
			"!packages/core",
			"packages/{oauth,session}",
			"packages/o*",
			"no-such-workspace",
		]) {
			expect(() => workspaceDirsIn(yaml(pattern), repoRoot), pattern).toThrow(pattern);
		}
	});

	it("refuses a file that names no workspace", () => {
		expect(() => workspaceDirsIn("packages:\n\nother: 1\n", repoRoot)).toThrow(/no workspace/);
	});
});

describe("no manifest outside core requires config but the ones CONFIG_REQUIRERS lists", () => {
	it("reads every manifest's requires and optional", () => {
		expect(
			FOUND.filter(
				(manifest) => manifest.requires === undefined || manifest.optional === undefined,
			).map((manifest) => `${manifest.file}:${manifest.line}`),
		).toEqual([]);
	});

	it("names every manifest that lists config", () => {
		expect(
			FOUND.filter((manifest) => manifest.name === undefined && readsConfig(manifest)).map(
				(manifest) => `${manifest.file}:${manifest.line}`,
			),
		).toEqual([]);
	});

	it("finds no manifest listing config beyond the list", () => {
		const requirers = FOUND.filter(readsConfig).map(
			(manifest) => `${manifest.workspace} -> ${manifest.name}`,
		);
		expect(
			requirers.filter((key) => !CONFIG_REQUIRERS.includes(key)),
			"a module reads its own section (deps.section) and another module's values through a slot",
		).toEqual([]);
	});

	it("keeps no entry whose manifest no longer lists config: the list only shrinks", () => {
		const requirers = new Set(
			FOUND.filter(readsConfig).map((manifest) => `${manifest.workspace} -> ${manifest.name}`),
		);
		expect(
			CONFIG_REQUIRERS.filter((key) => !requirers.has(key)),
			"remove it from CONFIG_REQUIRERS",
		).toEqual([]);
	});
});
