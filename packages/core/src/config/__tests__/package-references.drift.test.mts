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
 * Where a package keeps its defaults (#728): every package that ships a
 * `reference.conf` keeps it at `config/reference.conf`, publishes that
 * directory (`files` lists `config`), and exports the file as
 * `./reference.conf`. One place in every package, so a module's
 * `section.reference` — `new URL("../config/reference.conf",
 * import.meta.url)` from a file under `src/` — names the same file from the
 * source and from the published `dist/`, and a composition root that layers
 * what its modules declare finds it in an installed package.
 *
 * And the references are disjoint: no path is set by two of them, so the
 * order a composition layers them in decides nothing — and each package that
 * ships one checks it in its own tests with `packageReferenceProblems` from
 * core's testing entry.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const PACKAGES = join(REPO_ROOT, "packages");

/** Every `reference.conf` under a package, found by looking, relative to the repository. */
function shippedReferenceConfs(dir: string, found: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (["node_modules", "dist", "coverage"].includes(entry.name)) continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) shippedReferenceConfs(full, found);
		else if (entry.name === "reference.conf") found.push(relative(REPO_ROOT, full));
	}
	return found.sort();
}

const REFERENCES = shippedReferenceConfs(PACKAGES);

/**
 * Every path `path`'s reference sets, with each variable it substitutes set:
 * a path only an environment variable fills is one it sets too. A list is one
 * path.
 */
function pathsSetBy(path: string): string[] {
	const text = readFileSync(join(REPO_ROOT, path), "utf8");
	const env = Object.fromEntries(
		[...text.matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) => [String(match[1]), "set"]),
	);
	const leaves = (tree: unknown, prefix: string): string[] =>
		typeof tree === "object" &&
		tree !== null &&
		!Array.isArray(tree) &&
		Object.keys(tree).length > 0
			? Object.entries(tree).flatMap(([key, value]) =>
					leaves(value, prefix === "" ? key : `${prefix}.${key}`),
				)
			: prefix === ""
				? []
				: [prefix];
	return leaves(parseFile(join(REPO_ROOT, path), { env }).toObject(), "");
}

/** Every file under `dir`, relative to the repository, skipping build output. */
function sourceFiles(dir: string, found: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (["node_modules", "dist", "coverage"].includes(entry.name)) continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) sourceFiles(full, found);
		else found.push(full);
	}
	return found;
}

describe("every package keeps its defaults at config/reference.conf (#728)", () => {
	it("finds the packages that ship defaults (the guard is not vacuous)", () => {
		expect(REFERENCES).toEqual(
			expect.arrayContaining([
				expect.stringMatching(/^packages\/core\//),
				expect.stringMatching(/^packages\/webauthn\//),
			]),
		);
		expect(REFERENCES.length).toBeGreaterThanOrEqual(6);
	});

	it("keeps each one at config/reference.conf", () => {
		const misplaced = REFERENCES.filter(
			(path) => !/^packages\/[^/]+\/config\/reference\.conf$/.test(path),
		);
		expect(misplaced).toEqual([]);
	});

	it("publishes the config directory and exports the file as ./reference.conf", () => {
		const packages = [...new Set(REFERENCES.map((path) => path.split("/")[1] as string))];
		const unpublished = packages.flatMap((name) => {
			const manifest = JSON.parse(readFileSync(join(PACKAGES, name, "package.json"), "utf8")) as {
				files?: readonly string[];
				exports?: Record<string, unknown>;
			};
			const problems: string[] = [];
			if (!(manifest.files ?? []).includes("config")) {
				problems.push(`packages/${name}: files does not list config`);
			}
			if (manifest.exports?.["./reference.conf"] !== "./config/reference.conf") {
				problems.push(
					`packages/${name}: exports ./reference.conf as ${JSON.stringify(manifest.exports?.["./reference.conf"])}`,
				);
			}
			return problems;
		});
		expect(unpublished).toEqual([]);
	});
});

describe("the shipped references are disjoint, and each package checks its own (#728)", () => {
	const setBy = new Map<string, string[]>();
	for (const reference of REFERENCES) {
		for (const path of pathsSetBy(reference))
			setBy.set(path, [...(setBy.get(path) ?? []), reference]);
	}

	it("reads every reference's paths (the guard is not vacuous)", () => {
		expect(setBy.size).toBeGreaterThan(150);
	});

	it("sets no path in two references, so the order they are layered in decides nothing", () => {
		expect([...setBy].filter(([, references]) => references.length > 1)).toEqual([]);
	});

	it("sets no value at a path another reference sets keys under", () => {
		const paths = [...setBy.keys()];
		expect(
			paths.flatMap((outer) =>
				paths
					.filter((inner) => inner.startsWith(`${outer}.`))
					.map((inner) => `${outer} (${setBy.get(outer)}) holds ${inner} (${setBy.get(inner)})`),
			),
		).toEqual([]);
	});

	it("checks each package's reference in the package's own tests with packageReferenceProblems", () => {
		const packages = [...new Set(REFERENCES.map((path) => path.split("/")[1] as string))].filter(
			// Core's reference holds the sections core's schema declares; it is
			// checked against that schema (reference-conf-drift), not a module's.
			(name) => name !== "core",
		);
		const unchecked = packages.filter(
			(name) =>
				!sourceFiles(join(PACKAGES, name, "src")).some(
					(file) =>
						/\.test\.mts$/.test(file) &&
						readFileSync(file, "utf8").includes("packageReferenceProblems("),
				),
		);
		expect(unchecked).toEqual([]);
	});
});
