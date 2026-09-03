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
 * `removedIn` stamps vs. the CHANGELOG (#458).
 *
 * `withRemovedKeys` puts `removedIn` verbatim into the boot error an operator
 * reads when a retired key is still in their config. Per
 * docs/release-policy.md R5 a removal landing on HEAD carries a neutral
 * placeholder (`"this release (#330)"`), and R6 step 5 replaces it with the
 * released tag at cut time. The checklist missed one twice: `"this release
 * (#330)"` shipped in v0.10.0 and again in v0.11.0, pointing operators at a
 * release with no name.
 *
 * The guard follows the policy rather than fighting it: a stamp is either a
 * released tag (`vX.Y.Z ...`) or a placeholder whose PR the CHANGELOG still
 * lists under `## [Unreleased]`. The roll-up commit that moves the PR under a
 * version heading — the R6 pass itself — is the moment this starts failing,
 * and the failure names the section to copy the tag from.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../../..", import.meta.url));
const changelog = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");

interface Stamp {
	readonly file: string;
	readonly value: string;
}

/** Every `removedIn: "..."` literal in shipped source under `packages/`. */
function removedInStamps(): Stamp[] {
	const stamps: Stamp[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir)) {
			// Test fixtures stamp made-up tags (`v9.9.9 (test)`); no operator
			// reads those.
			if (entry === "node_modules" || entry === "dist" || entry === "__tests__") continue;
			const full = join(dir, entry);
			if (statSync(full).isDirectory()) {
				walk(full);
				continue;
			}
			if (!entry.endsWith(".mts")) continue;
			const source = readFileSync(full, "utf8");
			for (const match of source.matchAll(/removedIn:\s*"([^"]*)"/g)) {
				stamps.push({ file: relative(repoRoot, full), value: match[1] ?? "" });
			}
		}
	};
	walk(join(repoRoot, "packages"));
	return stamps;
}

/** CHANGELOG sections as `[heading, body]`, oldest first. */
function changelogSections(): [string, string][] {
	return changelog
		.split(/^(?=## \[)/m)
		.flatMap((section): [string, string][] => {
			const heading = /^## \[([^\]]+)\]/.exec(section)?.[1];
			return heading === undefined ? [] : [[heading, section]];
		})
		.reverse();
}

/** Whether `body` cites `#<pr>` (and not, say, `#3300` for pr `330`). */
const cites = (body: string, pr: string): boolean => new RegExp(`#${pr}(?!\\d)`).test(body);

/** A released tag, optionally followed by a marker: `v0.10.0 (#330)`. */
const RELEASED_TAG = /^v\d+\.\d+\.\d+(?:\s|$)/;

describe("removedIn stamps (#458)", () => {
	const stamps = removedInStamps();

	it("finds stamps at all — the scan is not vacuously passing", () => {
		expect(stamps.length).toBeGreaterThan(0);
	});

	it("names a released tag, or cites a PR the CHANGELOG still lists as unreleased", () => {
		const sections = changelogSections();
		const unreleased = sections.find(([heading]) => heading === "Unreleased")?.[1] ?? "";
		const stale = stamps.flatMap(({ file, value }) => {
			if (RELEASED_TAG.test(value)) return [];
			const pr = /#(\d+)/.exec(value)?.[1];
			if (pr === undefined) {
				return [
					`${file}: "${value}" is neither a released tag nor a placeholder citing its PR as #NNN`,
				];
			}
			if (cites(unreleased, pr)) return [];
			// Oldest section first: a later release may mention the PR in passing.
			const shipped = sections.find(
				([heading, body]) => heading !== "Unreleased" && cites(body, pr),
			);
			return [
				`${file}: "${value}" — #${pr} is under CHANGELOG ${shipped === undefined ? "no section" : `[${shipped[0]}]`}, ` +
					"not [Unreleased]; stamp the released tag (docs/release-policy.md R6 step 5)",
			];
		});
		expect(stale).toEqual([]);
	});
});
