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
 * The import edges between core's directories that `src/README.md` states as
 * rules and a test holds.
 *
 * Most of the boundaries that README draws are kept by review. The ones here
 * are kept by this suite because each was an entanglement that was taken
 * apart, and putting it back is one import away and looks harmless in a
 * diff: two directories importing each other's values (`jwks/` and `routes/`
 * did, through the JWKS router), and `replay-seen-set/` reaching into
 * `challenges/` for the pieces the two share, instead of both taking them
 * from the `single-use/` leaf.
 *
 * Read with TypeScript's parser rather than a pattern, because the rules turn
 * on whether an import is type-only: `import type` / `export type`, a clause
 * whose every named binding is marked `type`, or `import("…")` in a type
 * position. Anything else is a value import, `await import("…")` included.
 * Only relative specifiers are core's; a package name is not an edge here.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

/** `packages/core/src`. */
const srcDir = resolve(fileURLToPath(import.meta.url), "../..");

interface ImportEdge {
	/** The importing file, relative to `src/`, `/`-separated. */
	readonly from: string;
	/** The imported file, relative to `src/`, as its `.mts` source. */
	readonly to: string;
	readonly typeOnly: boolean;
}

/** Core's product sources: every `.mts` under `src/` outside `__tests__`. */
function productFiles(dir: string = srcDir): string[] {
	const files: string[] = [];
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return files;
	}
	for (const entry of entries) {
		if (entry.name === "__tests__") continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) files.push(...productFiles(full));
		else if (entry.name.endsWith(".mts") && !entry.name.endsWith(".d.mts")) files.push(full);
	}
	return files;
}

const fromSrc = (path: string): string => relative(srcDir, path).split(sep).join("/");

function importsOf(file: string): ImportEdge[] {
	const source = ts.createSourceFile(
		file,
		readFileSync(file, "utf8"),
		ts.ScriptTarget.Latest,
		true,
	);
	const edges: ImportEdge[] = [];
	const add = (specifier: string, typeOnly: boolean): void => {
		if (!specifier.startsWith(".")) return;
		const to = fromSrc(resolve(dirname(file), specifier)).replace(/\.mjs$/, ".mts");
		edges.push({ from: fromSrc(file), to, typeOnly });
	};
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
			const clause = node.importClause;
			const bindings = clause?.namedBindings;
			const typeOnly =
				clause !== undefined &&
				(clause.isTypeOnly ||
					(clause.name === undefined &&
						bindings !== undefined &&
						ts.isNamedImports(bindings) &&
						bindings.elements.length > 0 &&
						bindings.elements.every((element) => element.isTypeOnly)));
			add(node.moduleSpecifier.text, typeOnly);
		} else if (
			ts.isExportDeclaration(node) &&
			node.moduleSpecifier !== undefined &&
			ts.isStringLiteral(node.moduleSpecifier)
		) {
			const clause = node.exportClause;
			const typeOnly =
				node.isTypeOnly ||
				(clause !== undefined &&
					ts.isNamedExports(clause) &&
					clause.elements.length > 0 &&
					clause.elements.every((element) => element.isTypeOnly));
			add(node.moduleSpecifier.text, typeOnly);
		} else if (
			ts.isImportTypeNode(node) &&
			ts.isLiteralTypeNode(node.argument) &&
			ts.isStringLiteral(node.argument.literal)
		) {
			add(node.argument.literal.text, true);
		} else if (
			ts.isCallExpression(node) &&
			node.expression.kind === ts.SyntaxKind.ImportKeyword &&
			node.arguments[0] !== undefined &&
			ts.isStringLiteralLike(node.arguments[0])
		) {
			add(node.arguments[0].text, false);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return edges;
}

const EDGES: readonly ImportEdge[] = productFiles().flatMap(importsOf);

/** The edges from files under `from` to files under `to`, as `file -> file` lines. */
function edgesBetween(from: string, to: string, kind: "any" | "value"): string[] {
	return EDGES.filter(
		(edge) =>
			edge.from.startsWith(from) && edge.to.startsWith(to) && (kind === "any" || !edge.typeOnly),
	).map((edge) => `${edge.from} -> ${edge.to}${edge.typeOnly ? " (type)" : ""}`);
}

/**
 * The node an edge counts for: the directory directly under `src/` (with a
 * trailing `/`), or the file itself for one at the root.
 */
const nodeOf = (path: string): string =>
	path.includes("/") ? path.slice(0, path.indexOf("/") + 1) : path;

/** Every set of nodes that import one another's values, each sorted, sorted by first member. */
function valueCycles(): string[][] {
	const next = new Map<string, Set<string>>();
	for (const edge of EDGES) {
		const from = nodeOf(edge.from);
		const to = nodeOf(edge.to);
		if (edge.typeOnly || from === to) continue;
		next.set(from, (next.get(from) ?? new Set()).add(to));
	}
	// Tarjan's strongly connected components.
	const index = new Map<string, number>();
	const low = new Map<string, number>();
	const stack: string[] = [];
	const onStack = new Set<string>();
	const cycles: string[][] = [];
	const connect = (node: string): void => {
		index.set(node, index.size);
		low.set(node, index.get(node) as number);
		stack.push(node);
		onStack.add(node);
		for (const target of next.get(node) ?? []) {
			if (!index.has(target)) {
				connect(target);
				low.set(node, Math.min(low.get(node) as number, low.get(target) as number));
			} else if (onStack.has(target)) {
				low.set(node, Math.min(low.get(node) as number, index.get(target) as number));
			}
		}
		if (low.get(node) !== index.get(node)) return;
		const component: string[] = [];
		let member: string | undefined;
		do {
			member = stack.pop() as string;
			onStack.delete(member);
			component.push(member);
		} while (member !== node);
		if (component.length > 1) cycles.push(component.sort());
	};
	for (const node of next.keys()) if (!index.has(node)) connect(node);
	return cycles.sort((a, b) => (a[0] ?? "").localeCompare(b[0] ?? ""));
}

/**
 * The directory-level value cycles that stand, each with why. A stale entry —
 * a cycle that is gone — fails like a new cycle does, so the list cannot
 * outlive its reasons.
 */
const STANDING_VALUE_CYCLES: ReadonlyArray<{
	readonly members: readonly string[];
	readonly why: string;
}> = [
	{
		members: ["federation-grants/", "user-sessions/"],
		why: "subject-wide revocation ends grants through federation-grants/, and the grants' wiring rule reads a capability guard from user-sessions/; no file-level cycle crosses them (src/README.md, where a boundary is a judgement call)",
	},
];

describe("the import scan", () => {
	it("reads a type-only edge as type-only and a value edge as a value", () => {
		// A scan that classifies nothing, or everything the same way, would pass
		// every rule below vacuously.
		expect(EDGES).toContainEqual({
			from: "challenges/ceremony.mts",
			to: "replay-seen-set/types.mts",
			typeOnly: true,
		});
		expect(EDGES).toContainEqual({
			from: "replay-seen-set/module.mts",
			to: "modules/manifest/index.mts",
			typeOnly: false,
		});
	});
});

describe("challenges/ and replay-seen-set/ share their pieces through single-use/", () => {
	it("replay-seen-set/ imports nothing from challenges/", () => {
		// The key encoding, the storage error and the sweep pacing both stores
		// use live in single-use/, so the seen-set has no reason to reach here.
		expect(edgesBetween("replay-seen-set/", "challenges/", "any")).toEqual([]);
	});

	it("challenges/ takes only types from replay-seen-set/ — the port its ceremony composes", () => {
		expect(edgesBetween("challenges/", "replay-seen-set/", "value")).toEqual([]);
	});

	it("single-use/ holds the shared pieces and imports nothing else in core", () => {
		// A leaf: were it to import either store, each would reach the other
		// through it.
		expect(productFiles(join(srcDir, "single-use")).map(fromSrc)).toEqual(
			expect.arrayContaining([
				"single-use/canonical-key.mts",
				"single-use/errors.mts",
				"single-use/sweep.mts",
			]),
		);
		const outward = EDGES.filter(
			(edge) => edge.from.startsWith("single-use/") && !edge.to.startsWith("single-use/"),
		).map((edge) => `${edge.from} -> ${edge.to}`);
		expect(outward).toEqual([]);
	});
});

describe("no two of core's directories import each other's values", () => {
	it("finds no value cycle between directories but the ones that stand", () => {
		// `jwks/module.mts` contributed the router in `routes/Jwks.mts`, which
		// read the path rule and `Cache-Control` back from `jwks/`. Publishing
		// the key set is one job, so its router lives in `jwks/`.
		expect(valueCycles()).toEqual(
			STANDING_VALUE_CYCLES.map((cycle) => [...cycle.members].sort()).sort((a, b) =>
				(a[0] ?? "").localeCompare(b[0] ?? ""),
			),
		);
	});
});
