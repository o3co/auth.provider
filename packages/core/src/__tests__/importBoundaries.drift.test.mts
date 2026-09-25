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
 * did, through the JWKS router), `replay-seen-set/` reaching into
 * `challenges/` for the pieces the two share, instead of both taking them
 * from the `single-use/` leaf, and a leaf taking on a dependency — which
 * makes everything that imports the leaf depend on it too.
 *
 * Read with TypeScript's parser rather than a pattern, because the rules turn
 * on whether an import is type-only: `import type` / `export type`, a clause
 * whose every named binding is marked `type`, or `import("…")` in a type
 * position. Anything else is a value import, `await import("…")` included.
 * A relative specifier and a `#/…` one (the package's subpath import) name a
 * core file; any other package name is not an edge here.
 *
 * What the scan cannot turn into an edge it reports, and "sees every import
 * in core's product code" fails on it: core imported by its own package name,
 * an `import()` or `require()` of a computed specifier, a `require()` of a
 * core file, and an `import … = require(…)`. What it does not see at all: a
 * require function bound under another name than `require`.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, posix, relative, resolve, sep } from "node:path";
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

/**
 * The name core is published under. Core importing itself by it is an edge
 * the scan cannot resolve to a file; `declare module "…"`, which augments
 * `ComponentMap`, is not an import and is not read as one.
 */
const OWN_PACKAGE = "@o3co/auth-provider-core";

/** What the scan found in one source: its edges into core, and what it could not resolve. */
interface Scan {
	readonly edges: readonly ImportEdge[];
	/** `file:line: what` for each import the scan cannot turn into an edge. */
	readonly holes: readonly string[];
}

/** Scan `text` as the file at `from` (relative to `src/`). */
function scanSource(from: string, text: string): Scan {
	const source = ts.createSourceFile(from, text, ts.ScriptTarget.Latest, true);
	const edges: ImportEdge[] = [];
	const holes: string[] = [];
	const hole = (node: ts.Node, what: string): void => {
		const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
		holes.push(`${from}:${line}: ${what}`);
	};
	/** The core file `specifier` names, relative to `src/`; undefined for a package. */
	const coreFile = (specifier: string): string | undefined => {
		const path = specifier.startsWith(".")
			? posix.normalize(posix.join(posix.dirname(from), specifier))
			: specifier.startsWith("#/")
				? specifier.slice(2)
				: undefined;
		return path?.replace(/\.mjs$/, ".mts");
	};
	const isOwnPackage = (specifier: string): boolean =>
		specifier === OWN_PACKAGE || specifier.startsWith(`${OWN_PACKAGE}/`);
	const add = (node: ts.Node, specifier: string, typeOnly: boolean): void => {
		if (isOwnPackage(specifier)) {
			hole(node, `an import of core by its package name, ${specifier}`);
			return;
		}
		const to = coreFile(specifier);
		if (to !== undefined) edges.push({ from, to, typeOnly });
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
			add(node, node.moduleSpecifier.text, typeOnly);
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
			add(node, node.moduleSpecifier.text, typeOnly);
		} else if (
			ts.isImportTypeNode(node) &&
			ts.isLiteralTypeNode(node.argument) &&
			ts.isStringLiteral(node.argument.literal)
		) {
			add(node, node.argument.literal.text, true);
		} else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
			const argument = node.arguments[0];
			if (argument !== undefined && ts.isStringLiteralLike(argument)) {
				add(node, argument.text, false);
			} else {
				hole(node, "an import() of a computed specifier");
			}
		} else if (
			ts.isCallExpression(node) &&
			ts.isIdentifier(node.expression) &&
			node.expression.text === "require"
		) {
			// `createRequire` is how core loads `express`, an optional peer. A
			// package is not an edge; a core file loaded this way would be one
			// the scan does not see, so it is refused rather than guessed at.
			const argument = node.arguments[0];
			if (argument === undefined || !ts.isStringLiteralLike(argument)) {
				hole(node, "a require() of a computed specifier");
			} else if (isOwnPackage(argument.text)) {
				hole(node, `an import of core by its package name, ${argument.text}`);
			} else if (coreFile(argument.text) !== undefined) {
				hole(node, `a require() of core's own ${argument.text}`);
			}
		} else if (
			ts.isImportEqualsDeclaration(node) &&
			ts.isExternalModuleReference(node.moduleReference)
		) {
			const expression = node.moduleReference.expression;
			hole(
				node,
				`an import-equals require of ${ts.isStringLiteralLike(expression) ? expression.text : "a computed specifier"}`,
			);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return { edges, holes };
}

const SCANS: readonly Scan[] = productFiles().map((file) =>
	scanSource(fromSrc(file), readFileSync(file, "utf8")),
);

const EDGES: readonly ImportEdge[] = SCANS.flatMap((scan) => scan.edges);

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

/** Every set of `node`s that import one another's values, each sorted, sorted by first member. */
function valueCycles(node: (path: string) => string): string[][] {
	const next = new Map<string, Set<string>>();
	for (const edge of EDGES) {
		const from = node(edge.from);
		const to = node(edge.to);
		if (edge.typeOnly || from === to) continue;
		next.set(from, (next.get(from) ?? new Set()).add(to));
	}
	// Tarjan's strongly connected components.
	const index = new Map<string, number>();
	const low = new Map<string, number>();
	const stack: string[] = [];
	const onStack = new Set<string>();
	const cycles: string[][] = [];
	const connect = (current: string): void => {
		index.set(current, index.size);
		low.set(current, index.get(current) as number);
		stack.push(current);
		onStack.add(current);
		for (const target of next.get(current) ?? []) {
			if (!index.has(target)) {
				connect(target);
				low.set(current, Math.min(low.get(current) as number, low.get(target) as number));
			} else if (onStack.has(target)) {
				low.set(current, Math.min(low.get(current) as number, index.get(target) as number));
			}
		}
		if (low.get(current) !== index.get(current)) return;
		const component: string[] = [];
		let member: string | undefined;
		do {
			member = stack.pop() as string;
			onStack.delete(member);
			component.push(member);
		} while (member !== current);
		if (component.length > 1) cycles.push(component.sort());
	};
	for (const start of next.keys()) if (!index.has(start)) connect(start);
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
		why: "subject-wide revocation ends grants through federation-grants/, and the grants' wiring rule reads a capability guard from user-sessions/; no cycle of value imports between their files closes, which the file-level case below holds (src/README.md, where a boundary is a judgement call)",
	},
];

describe("the import scan", () => {
	it("maps a `#/` specifier — core's own subpath import — to the file it names", () => {
		const { edges, holes } = scanSource(
			"adapters/example.mts",
			[
				'import { isLoopbackHostname } from "#/net/loopback.mjs";',
				'import type { Logger } from "#/logging/Logger.mjs";',
			].join("\n"),
		);
		expect(edges).toEqual([
			{ from: "adapters/example.mts", to: "net/loopback.mts", typeOnly: false },
			{ from: "adapters/example.mts", to: "logging/Logger.mts", typeOnly: true },
		]);
		expect(holes).toEqual([]);
	});

	it("reports what it cannot resolve instead of passing over it", () => {
		const { holes } = scanSource(
			"adapters/example.mts",
			[
				'import { createApp } from "@o3co/auth-provider-core";',
				'export * from "@o3co/auth-provider-core/testing";',
				"const loaded = await import(specifier);",
				'const sibling = require("./sibling.mjs");',
				"const computed = require(specifier);",
				'import legacy = require("./legacy");',
			].join("\n"),
		);
		expect(holes).toEqual([
			"adapters/example.mts:1: an import of core by its package name, @o3co/auth-provider-core",
			"adapters/example.mts:2: an import of core by its package name, @o3co/auth-provider-core/testing",
			"adapters/example.mts:3: an import() of a computed specifier",
			"adapters/example.mts:4: a require() of core's own ./sibling.mjs",
			"adapters/example.mts:5: a require() of a computed specifier",
			"adapters/example.mts:6: an import-equals require of ./legacy",
		]);
	});

	it("passes over what is not core: a package, and the ComponentMap augmentation", () => {
		const { edges, holes } = scanSource(
			"jwks/example.mts",
			[
				'import { z } from "zod";',
				'const express = require("express");',
				'const lazy = await import("express");',
				'declare module "@o3co/auth-provider-core" { interface ComponentMap { readonly x?: number } }',
			].join("\n"),
		);
		expect(edges).toEqual([]);
		expect(holes).toEqual([]);
	});

	it("sees every import in core's product code", () => {
		expect(SCANS.flatMap((scan) => scan.holes)).toEqual([]);
	});

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

	it("single-use/ holds the shared pieces", () => {
		// It imports nothing outside itself: see the leaves below. Were it to
		// import either store, each would reach the other through it.
		expect(productFiles(join(srcDir, "single-use")).map(fromSrc)).toEqual(
			expect.arrayContaining([
				"single-use/canonical-key.mts",
				"single-use/errors.mts",
				"single-use/sweep.mts",
			]),
		);
	});
});

/**
 * The leaves `src/README.md` names, and the edges out of them that stand,
 * each with why. A leaf is imported from everywhere, so what it imports
 * everything imports. Each edge is a file-to-file import with its kind: a new
 * edge, a type-only edge that became a value import, a second file taking the
 * same import, or an edge that is gone all fail, so the list says what holds
 * now.
 */
const LEAVES: Readonly<
	Record<string, ReadonlyArray<{ readonly edge: string; readonly why: string }>>
> = {
	"adapters/": [
		{
			edge: "adapters/AdapterFactory.mts -> logging/Logger.mts (type)",
			why: "`BuilderContext.logger`, the logger a builder reports its connection's errors through, and `EventLogger`, the one method the lifecycle drain logs a failed cleanup through",
		},
		{
			edge: "adapters/AdapterFactory.mts -> logging/loggableError.mts",
			why: "the lifecycle drain logs a failed cleanup's error through the one projection a log line may carry",
		},
		{
			edge: "adapters/AdapterFactory.mts -> readiness/types.mts (type)",
			why: "`BuilderContext.readiness` is the registrar a builder that opens a connection registers its probe into",
		},
	],
	"errors/": [
		{
			edge: "errors/envelope.mts -> logging/consoleLogger.mts",
			why: "`errorEnvelope` warns when it is handed a malformed error code or `error_uri`; it takes no logger, so it writes to `consoleLogger`",
		},
	],
	"logging/": [],
	"net/": [],
	"security/": [],
	"single-use/": [],
};

describe("core's leaves import nothing else in core but the edges listed", () => {
	it("checks exactly the leaves src/README.md names", () => {
		// The rule is the README's; a leaf added there and not here, or kept
		// here after the README dropped it, would be a rule nobody holds.
		const readme = readFileSync(join(srcDir, "README.md"), "utf8");
		const bullet = readme.split("\n").find((line) => / are leaves:/.test(line));
		expect(bullet, "src/README.md's leaf bullet").toBeDefined();
		const named = [...(bullet ?? "").split(" are leaves:")[0].matchAll(/`([\w-]+\/)`/g)].map(
			(match) => match[1],
		);
		expect(named.sort()).toEqual(Object.keys(LEAVES).sort());
	});

	it.each(Object.keys(LEAVES))("%s", (leaf) => {
		expect(productFiles(join(srcDir, leaf)).length, `${leaf} holds product code`).toBeGreaterThan(
			0,
		);
		const outward = EDGES.filter(
			(edge) => edge.from.startsWith(leaf) && !edge.to.startsWith(leaf),
		).map((edge) => `${edge.from} -> ${edge.to}${edge.typeOnly ? " (type)" : ""}`);
		expect(outward.sort()).toEqual((LEAVES[leaf] ?? []).map((allowed) => allowed.edge).sort());
	});
});

describe("no two of core's files import each other's values", () => {
	it("finds no value cycle between files anywhere in core", () => {
		// What src/README.md and the standing directory cycle's reason claim:
		// even where two directories depend on each other, no chain of value
		// imports leads from a file back to itself.
		expect(valueCycles((path) => path)).toEqual([]);
	});
});

describe("no two of core's directories import each other's values", () => {
	it("finds no value cycle between directories but the ones that stand", () => {
		// `jwks/module.mts` contributed the router in `routes/Jwks.mts`, which
		// read the path rule and `Cache-Control` back from `jwks/`. Publishing
		// the key set is one job, so its router lives in `jwks/`.
		expect(valueCycles(nodeOf)).toEqual(
			STANDING_VALUE_CYCLES.map((cycle) => [...cycle.members].sort()).sort((a, b) =>
				(a[0] ?? "").localeCompare(b[0] ?? ""),
			),
		);
	});
});
