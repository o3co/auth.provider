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
 * Where a package keeps its defaults: every package that ships a
 * `reference.conf` keeps it at `config/reference.conf`, publishes that
 * directory (`files` lists `config`), and exports it as `./reference.conf`,
 * so a module's `section.reference` (`new URL("../config/reference.conf",
 * import.meta.url)` from a file under `src/`) names the same file from the
 * source, from the published `dist/` and in an installed package.
 *
 * The references are disjoint — no path is set by two of them — so the order
 * a composition layers them in decides nothing; each package that ships one
 * checks it in its own tests with `packageReferenceProblems`.
 */

import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
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
 * Every path the reference at `file` sets, parsed on its own as a composition
 * parses each reference it layers, with each variable it substitutes set: a
 * path only an environment variable fills is one it sets too. A list is one
 * path.
 */
function pathsSetBy(file: string): string[] {
	const text = readFileSync(file, "utf8");
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
	return leaves(parseFile(file, { env }).toObject(), "");
}

/**
 * What two of `files` both set, one line each, sorted: a leaf both set, or a
 * value one sets at a path another sets keys under. Two references may each
 * hold keys under one section; neither may set what the other sets. Each
 * file is named by `label`.
 */
function overlapsAmong(
	files: readonly string[],
	label: (file: string) => string = (file) => file,
): string[] {
	const setBy = new Map<string, string[]>();
	for (const file of files) {
		for (const path of pathsSetBy(file)) setBy.set(path, [...(setBy.get(path) ?? []), label(file)]);
	}
	const paths = [...setBy.keys()];
	return [
		...[...setBy]
			.filter(([, owners]) => owners.length > 1)
			.map(([path, owners]) => `${path}: set by ${owners.join(" and ")}`),
		...paths.flatMap((outer) =>
			paths
				.filter((inner) => inner.startsWith(`${outer}.`))
				.map(
					(inner) =>
						`${outer}: a value in ${setBy.get(outer)?.join(" and ")}, keys under it (${inner}) in ${setBy.get(inner)?.join(" and ")}`,
				),
		),
	].sort();
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

describe("every package keeps its defaults at config/reference.conf", () => {
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

describe("the shipped references are disjoint, and each package checks its own", () => {
	const files = REFERENCES.map((path) => join(REPO_ROOT, path));
	const label = (file: string) => relative(REPO_ROOT, file);

	it("reads every reference's paths, core's among them (the guard is not vacuous)", () => {
		expect(REFERENCES).toContain("packages/core/config/reference.conf");
		expect(new Set(files.flatMap((file) => pathsSetBy(file))).size).toBeGreaterThan(150);
	});

	it("sets no leaf in two references, and no value where another sets keys: the order they are layered in decides nothing", () => {
		expect(overlapsAmong(files, label)).toEqual([]);
	});

	describe("finds an overlap between two references", () => {
		/** Two references written to a directory of their own. */
		const pair = (first: string, second: string): string[] => {
			const dir = mkdtempSync(join(tmpdir(), "package-references-"));
			const a = join(dir, "a.conf");
			const b = join(dir, "b.conf");
			writeFileSync(a, first);
			writeFileSync(b, second);
			return [a, b];
		};
		const named = (file: string) => basename(file);

		it("names a leaf both set", () => {
			const files = pair(
				"oauth.widget { enabled = false, size = 1 }\n",
				"oauth.widget.enabled = true\n",
			);
			expect(overlapsAmong(files, named)).toEqual([
				"oauth.widget.enabled: set by a.conf and b.conf",
			]);
		});

		it("names a leaf one sets only from an environment variable", () => {
			const files = pair(`oauth.widget.size = \${?WIDGET_SIZE}\n`, "oauth.widget.size = 2\n");
			expect(overlapsAmong(files, named)).toEqual(["oauth.widget.size: set by a.conf and b.conf"]);
		});

		it("names a value one sets where the other sets keys", () => {
			const files = pair('oauth.widget = "on"\n', "oauth.widget.enabled = true\n");
			expect(overlapsAmong(files, named)).toEqual([
				"oauth.widget: a value in a.conf, keys under it (oauth.widget.enabled) in b.conf",
			]);
		});

		it("finds none where both hold keys under one section, but no leaf in common", () => {
			const files = pair("oauth.widget.size = 1\n", 'oauth.widget.color = "red"\n');
			expect(overlapsAmong(files, named)).toEqual([]);
		});
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
