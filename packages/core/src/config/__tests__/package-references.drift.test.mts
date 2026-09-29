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
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
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
