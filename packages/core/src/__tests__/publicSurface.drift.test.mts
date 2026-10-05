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
 * Core's public surface: every key of `package.json`'s `exports`, and every
 * name each code entry exports, as a value or as a type only. It is pinned in
 * `packages/core/public-surface.txt`, one sorted line each:
 * `exports <key>`, and `<key> <name> value|type`.
 *
 * A code entry is a key whose `import` target is a `./dist/….mjs` file; its
 * names are read from the matching `./src/….mts` source with TypeScript's
 * checker, in one program over every entry. A name is a type when the export
 * is type-only anywhere along its alias chain (`export type`, `type X` in a
 * clause, a re-export of an `import type`), or when what it finally names has
 * no value meaning; otherwise it is a value. An entry may not use `export *`
 * (or `export * as ns`): every name it publishes is listed in it by hand.
 *
 * Updating: a change to the surface fails here with the names added and
 * removed. Re-run this file with vitest's `-u` to rewrite the snapshot, and
 * commit it in the same PR:
 *
 *   pnpm --filter @o3co/auth-provider-core exec vitest run src/__tests__/publicSurface.drift.test.mts -u
 *
 * An added name is a public API addition. A removed or renamed one, or a
 * value that became a type only, breaks consumers, and needs a CHANGELOG line
 * at the release cut.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

/** `packages/core`. */
const packageDir = resolve(fileURLToPath(import.meta.url), "../../..");
const SNAPSHOT = join(packageDir, "public-surface.txt");

const BREAKING_NOTE =
	"An added name is a deliberate public API addition; a removed or renamed name is BREAKING and needs a CHANGELOG line at the release cut. Update public-surface.txt in the same PR.";

/** A key of `exports` whose target is code, and the source it is built from. */
interface CodeEntry {
	readonly key: string;
	readonly source: string;
}

/** The `exports` keys, in file order, and those of them that are code entries. */
function readExports(): {
	readonly keys: readonly string[];
	readonly entries: readonly CodeEntry[];
} {
	const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")) as {
		exports: Record<string, string | Record<string, string>>;
	};
	const keys = Object.keys(manifest.exports);
	const entries: CodeEntry[] = [];
	for (const key of keys) {
		const target = manifest.exports[key];
		const runtime = typeof target === "string" ? target : target?.import;
		const built = runtime === undefined ? null : /^\.\/dist\/(.+)\.mjs$/.exec(runtime);
		if (built === null) continue;
		const source = join(packageDir, "src", `${built[1]}.mts`);
		if (!existsSync(source)) throw new Error(`exports["${key}"] has no source at ${source}`);
		entries.push({ key, source });
	}
	return { keys, entries };
}

/**
 * Probe modules, typed in the same program as the entries, that hold the
 * value/type reading and the `export *` refusal to the cases they turn on.
 */
const PROBE_DIR = join(packageDir, "src/__tests__");
const PROBES = new Map<string, string>([
	[
		join(PROBE_DIR, "__public_surface_probe_declarations__.mts"),
		[
			"export const aConst = 1;",
			"export function aFunction(): void {}",
			"export class AClass {}",
			"export class TypeOnlyClass {}",
			"export enum AnEnum { A }",
			"export namespace AValueNamespace { export const x = 1; }",
			"export interface AnInterface {}",
			"export type AnAlias = string;",
			"export const Merged = 1;",
			"export type Merged = number;",
		].join("\n"),
	],
	[
		join(PROBE_DIR, "__public_surface_probe__.mts"),
		[
			'import type { AClass } from "./__public_surface_probe_declarations__.mjs";',
			"export {",
			"\taConst, aFunction, AnEnum, AValueNamespace, Merged, AnInterface, AnAlias,",
			"\ttype TypeOnlyClass,",
			'} from "./__public_surface_probe_declarations__.mjs";',
			"export { AClass };",
		].join("\n"),
	],
	[
		join(PROBE_DIR, "__public_surface_probe_star__.mts"),
		[
			'export * from "./__public_surface_probe_declarations__.mjs";',
			'export * as declarations from "./__public_surface_probe_declarations__.mjs";',
			'export { aConst } from "./__public_surface_probe_declarations__.mjs";',
		].join("\n"),
	],
]);
const [, PROBE, STAR_PROBE] = [...PROBES.keys()] as [string, string, string];

/** One program over every code entry and the probes, under core's own compiler options. */
function surfaceProgram(roots: readonly string[]): ts.Program {
	const parsed = ts.getParsedCommandLineOfConfigFile(
		join(packageDir, "tsconfig.json"),
		{ noEmit: true, types: [] },
		{
			...ts.sys,
			onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
				throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));
			},
		},
	);
	if (parsed === undefined) throw new Error("packages/core/tsconfig.json could not be read");
	const host = ts.createCompilerHost(parsed.options, true);
	host.jsDocParsingMode = ts.JSDocParsingMode.ParseForTypeInfo;
	const readFile = host.readFile.bind(host);
	const fileExists = host.fileExists.bind(host);
	const getSourceFile = host.getSourceFile.bind(host);
	host.readFile = (f) => PROBES.get(f) ?? readFile(f);
	host.fileExists = (f) => PROBES.has(f) || fileExists(f);
	host.getSourceFile = (f, language, onError, create) => {
		const probe = PROBES.get(f);
		return probe === undefined
			? getSourceFile(f, language, onError, create)
			: ts.createSourceFile(f, probe, language, true, ts.ScriptKind.TS);
	};
	return ts.createProgram({
		rootNames: [...roots, ...PROBES.keys()],
		options: parsed.options,
		host,
	});
}

/** `file:line` of each `export *` / `export * as ns` statement in `file`. */
function exportStars(file: ts.SourceFile): string[] {
	return file.statements
		.filter(
			(statement) =>
				ts.isExportDeclaration(statement) &&
				(statement.exportClause === undefined || ts.isNamespaceExport(statement.exportClause)),
		)
		.map(
			(statement) =>
				`${file.fileName}:${file.getLineAndCharacterOfPosition(statement.getStart(file)).line + 1}`,
		);
}

/** The names `file` exports, as sorted `<name> value|type` pairs. */
function namesOf(checker: ts.TypeChecker, file: ts.SourceFile): string[] {
	const moduleSymbol = checker.getSymbolAtLocation(file);
	if (moduleSymbol === undefined) return [];
	const kindOf = (symbol: ts.Symbol): "value" | "type" => {
		for (let link: ts.Symbol | undefined = symbol; link !== undefined; ) {
			if (link.declarations?.some((d) => ts.isTypeOnlyImportOrExportDeclaration(d))) return "type";
			if ((link.flags & ts.SymbolFlags.Alias) === 0) break;
			const next: ts.Symbol | undefined = checker.getImmediateAliasedSymbol(link);
			link = next === link ? undefined : next;
		}
		const target =
			(symbol.flags & ts.SymbolFlags.Alias) === 0 ? symbol : checker.getAliasedSymbol(symbol);
		if (target.declarations === undefined || target.declarations.length === 0) {
			throw new Error(`${file.fileName}: export ${symbol.name} does not resolve`);
		}
		return (target.flags & ts.SymbolFlags.Value) === 0 ? "type" : "value";
	};
	return checker
		.getExportsOfModule(moduleSymbol)
		.map((symbol) => `${symbol.name} ${kindOf(symbol)}`)
		.sort();
}

const { keys, entries } = readExports();
const program = surfaceProgram(entries.map((entry) => entry.source));
const checker = program.getTypeChecker();
const sourceOf = (path: string): ts.SourceFile => {
	const file = program.getSourceFile(path);
	if (file === undefined) throw new Error(`not in the program: ${path}`);
	return file;
};
const surface = [
	...keys.map((key) => `exports ${key}`),
	...entries.flatMap((entry) =>
		namesOf(checker, sourceOf(entry.source)).map((line) => `${entry.key} ${line}`),
	),
].sort();

describe("core's public surface", () => {
	it("reads a name's value or type meaning along its alias chain", () => {
		expect(namesOf(checker, sourceOf(PROBE))).toEqual([
			"AClass type",
			"AValueNamespace value",
			"AnAlias type",
			"AnEnum value",
			"AnInterface type",
			"Merged value",
			"TypeOnlyClass type",
			"aConst value",
			"aFunction value",
		]);
	});

	it("finds both forms of export *", () => {
		expect(exportStars(sourceOf(STAR_PROBE)).map((at) => at.replace(/^.*:/, "line "))).toEqual([
			"line 1",
			"line 2",
		]);
	});

	it("reads at least one code entry, the root among them", () => {
		expect(entries.map((entry) => entry.key)).toContain(".");
	});

	it("has no export * in any code entry", () => {
		expect(entries.flatMap((entry) => exportStars(sourceOf(entry.source)))).toEqual([]);
	});

	it("matches public-surface.txt", async () => {
		const pinned = existsSync(SNAPSHOT) ? readFileSync(SNAPSHOT, "utf8").split("\n") : [];
		const pinnedSet = new Set(pinned.filter((line) => line !== ""));
		const currentSet = new Set(surface);
		const added = surface.filter((line) => !pinnedSet.has(line));
		const removed = [...pinnedSet].filter((line) => !currentSet.has(line));
		const message = [
			BREAKING_NOTE,
			...added.map((line) => `  added:   ${line}`),
			...removed.map((line) => `  removed: ${line}`),
		].join("\n");
		await expect(`${surface.join("\n")}\n`, message).toMatchFileSnapshot(SNAPSHOT);
	});
});
