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
 * designVocabulary.drift.test.mts — the design-vocabulary map, executable
 * (#370).
 *
 * `docs/design-vocabulary.md` binds each top-down design concept to the one
 * bottom-up module that implements it. This suite is the enforcement half:
 * for every mapped concept with a greppable definition signature, it walks
 * every package's shipped source and fails when the signature is *defined*
 * anywhere but the mapped home.
 *
 * Why this exists: the 38-commit campaign review (2026-08-28) found that
 * design erosion in this repo does not live in files — it lives in
 * vocabularies. `isLoopbackHostname` was defined twice under identical doc
 * comments with different behavior (#364), one commit after the decision not
 * to unify was written down. Per-PR review cannot catch a second definition
 * it never sees; a drift guard can. Same pattern as the #288 env-var drift
 * guards: the property is owned by a test, not by everyone's memory.
 *
 * Adding a row: implement the concept in ONE module, add it to
 * `docs/design-vocabulary.md`, and add its definition signature here.
 * Re-exports (`export { x } from ...`) and imports deliberately do not match
 * the definition patterns — consumers may re-export the mapped home freely.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/**
 * One row of the vocabulary map. `definition` matches the *definition* form
 * only (`function x` / `const x =`), never an import or a re-export, so a
 * consumer package can re-export the home's symbol without tripping the
 * guard.
 */
interface VocabularyRow {
	readonly concept: string;
	/** Repo-relative path of the one module allowed to define it. */
	readonly home: string;
	readonly definition: RegExp;
}

const VOCABULARY: readonly VocabularyRow[] = [
	{
		concept: "loopback hostname (#364)",
		home: "packages/core/src/net/loopback.mts",
		definition: /(?:function|const)\s+isLoopbackHostname\b/,
	},
	{
		concept: "trusted-proxy address vocabulary (#292)",
		home: "packages/core/src/net/trusted-proxy.mts",
		definition: /(?:function|const)\s+(?:checkTrustedProxyEntry|createTrustedProxyMatcher)\b/,
	},
	{
		concept: "cnf/token-binding comparison matrix (#324)",
		home: "packages/core/src/grants/confirmationMatch.mts",
		definition: /(?:function|const)\s+matchConfirmation\b/,
	},
	{
		concept: "rate-limit guard (#325)",
		home: "packages/core/src/ratelimit/guard.mts",
		definition: /(?:function|const)\s+createRateLimitGuard\b/,
	},
	{
		concept: "retired config key (#366)",
		home: "packages/core/src/config/removed-keys.mts",
		definition: /(?:function|const)\s+withRemovedKeys\b/,
	},
];

/** Every shipped source file across the workspace: packages/*\/src\/**\/*.mts, tests excluded. */
function listShippedSources(): string[] {
	const files: string[] = [];
	const packagesDir = join(repoRoot, "packages");
	for (const pkg of readdirSync(packagesDir, { withFileTypes: true })) {
		if (!pkg.isDirectory()) continue;
		const srcDir = join(packagesDir, pkg.name, "src");
		walk(srcDir, files);
	}
	return files;
}

function walk(dir: string, out: string[]): void {
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return; // package without src/
	}
	for (const entry of entries) {
		if (entry.name === "__tests__" || entry.name === "node_modules") continue;
		const path = join(dir, entry.name);
		if (entry.isDirectory()) walk(path, out);
		else if (entry.name.endsWith(".mts")) out.push(path);
	}
}

describe("design-vocabulary map (docs/design-vocabulary.md)", () => {
	const sources = listShippedSources();

	it("walks a plausible workspace (sanity: the guard is not vacuous)", () => {
		expect(sources.length).toBeGreaterThan(50);
	});

	it("documents every enforced row", () => {
		const doc = readFileSync(join(repoRoot, "docs/design-vocabulary.md"), "utf8");
		for (const row of VOCABULARY) {
			// The doc names the home path, so map and guard cannot drift apart.
			expect(doc, `docs/design-vocabulary.md must name ${row.home}`).toContain(row.home);
		}
	});

	it.each(VOCABULARY.map((row) => [row.concept, row] as const))(
		"%s is defined only in its mapped home",
		(_concept, row) => {
			const home = join(repoRoot, row.home);
			expect(
				row.definition.test(readFileSync(home, "utf8")),
				`${row.home} must define the concept it is mapped as the home of`,
			).toBe(true);

			const offenders = sources
				.filter((file) => file !== home)
				.filter((file) => row.definition.test(readFileSync(file, "utf8")))
				.map((file) => relative(repoRoot, file));
			expect(
				offenders,
				`defined outside its mapped home — import (or re-export) ${row.home} instead`,
			).toEqual([]);
		},
	);
});
