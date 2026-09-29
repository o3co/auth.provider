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
 * The relocated-path refusal is removed at the first major release.
 *
 * A setting still written at a section's old path refuses boot naming the new
 * one (`section.relocatedFrom`, enforced as `config-path-relocated`). That
 * bridge is for the 0.x line only, and nothing in a release cut would remember
 * to remove it. So this fails from the cut that writes the first major
 * version's section in the CHANGELOG (written at cut time,
 * docs/release-policy.md R2) until `relocatedFrom` and
 * `config-path-relocated` are gone from core's source.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../../..", import.meta.url));
const coreSrc = join(repoRoot, "packages/core/src");

/** The newest released version a CHANGELOG lists, as `[major, minor, patch]`. */
function newestRelease(changelog: string): readonly [number, number, number] | undefined {
	const versions = [...changelog.matchAll(/^## \[(\d+)\.(\d+)\.(\d+)\]/gm)].map(
		(match) => [Number(match[1]), Number(match[2]), Number(match[3])] as const,
	);
	return versions.sort((a, b) => b[0] - a[0] || b[1] - a[1] || b[2] - a[2])[0];
}

/** Whether a release retires the relocated-path refusal. */
const retiresRelocations = (release: readonly [number, number, number] | undefined): boolean =>
	release !== undefined && release[0] >= 1;

/** Core's product sources that still name the relocation vocabulary. */
function sourcesNamingRelocations(dir: string = coreSrc): string[] {
	const found: string[] = [];
	for (const entry of readdirSync(dir)) {
		if (entry === "__tests__") continue;
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) {
			found.push(...sourcesNamingRelocations(full));
			continue;
		}
		if (!entry.endsWith(".mts")) continue;
		const text = readFileSync(full, "utf8");
		if (/relocatedFrom|config-path-relocated/.test(text)) found.push(relative(repoRoot, full));
	}
	return found;
}

describe("relocated-path refusals are removed at the first major release", () => {
	it("reads the newest release a CHANGELOG lists", () => {
		expect(
			newestRelease("## [0.16.0] - 2026-09-26\n\n## [0.9.0] - 2026-01-01\n## [0.15.2] - x\n"),
		).toEqual([0, 16, 0]);
		expect(newestRelease("# Changelog\n")).toBeUndefined();
	});

	it("retires them from the first major release on, and not before", () => {
		expect(retiresRelocations([0, 99, 0])).toBe(false);
		expect(retiresRelocations([1, 0, 0])).toBe(true);
		expect(retiresRelocations(undefined)).toBe(false);
	});

	it("finds the vocabulary today — the scan is not vacuously passing", () => {
		expect(sourcesNamingRelocations().length).toBeGreaterThan(0);
	});

	it("leaves no relocation in core's source once the first major version's section is written", () => {
		const changelog = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
		const remaining = retiresRelocations(newestRelease(changelog))
			? sourcesNamingRelocations()
			: [];
		expect(
			remaining,
			"the first major release retires relocatedFrom and config-path-relocated (#728 B10): delete them",
		).toEqual([]);
	});
});
