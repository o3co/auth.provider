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

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The build emits every `src/**/*.mts` outside `__tests__` (tsconfig.json's
// `exclude`), and the package publishes all of `dist` (package.json `files`).
// A source file the entry point does not reach therefore ships without being
// part of the package: `exports` (".") keeps it from being imported by package
// name, but it is still dead weight in the tarball. Scaffolding that only tests
// use belongs under `__tests__`, where the build does not look.
const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(SRC, "index.mts");

function emittedSources(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) return entry.name === "__tests__" ? [] : emittedSources(path);
		return entry.name.endsWith(".mts") ? [path] : [];
	});
}

// Relative specifiers of imports and re-exports, static or dynamic. Source files
// import each other relatively, naming the emitted `.mjs` (AGENTS.md "Module
// Resolution").
const RELATIVE_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g;

function reachableFrom(entry: string): ReadonlySet<string> {
	const reached = new Set<string>();
	const pending = [entry];
	for (let file = pending.pop(); file !== undefined; file = pending.pop()) {
		if (reached.has(file)) continue;
		reached.add(file);
		for (const match of readFileSync(file, "utf8").matchAll(RELATIVE_SPECIFIER)) {
			const specifier = match[1];
			if (specifier) pending.push(resolve(dirname(file), specifier.replace(/\.mjs$/, ".mts")));
		}
	}
	return reached;
}

describe("published files", () => {
	it("every source file the build emits is reachable from the package entry", () => {
		const reachable = reachableFrom(ENTRY);
		const unreachable = emittedSources(SRC)
			.filter((file) => !reachable.has(file))
			.map((file) => relative(SRC, file));
		expect(unreachable).toEqual([]);
	});
});
