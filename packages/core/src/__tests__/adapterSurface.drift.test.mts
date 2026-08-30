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
 * `docs/adapter-surface.md` vs. the slots that actually exist (#305).
 *
 * The epic's last open item is documenting the adapter surface "so implementers
 * cannot drift across it". A document that lists 49 slots drifts the week after
 * it is written unless something checks it, and a stale inventory is worse than
 * none: it reads as authoritative while omitting the slot someone is looking
 * for.
 *
 * Three directions, each for a way this goes wrong:
 *
 *  1. **Every declared slot is documented.** The new-slot case — added to
 *     `ComponentMap`, never written down.
 *  2. **Every documented slot still exists.** The removal case — the doc keeps
 *     describing a seam that is gone, and someone builds against it.
 *  3. **Every file the doc names is on disk.** The doc points implementers at
 *     conformance suites by path; a path that does not resolve sends them
 *     looking for something that was moved or never landed. This one caught a
 *     real mistake on its first run.
 *
 * Modelled on `campaignVocabulary.drift.test.mts`, which does the same job for
 * the design-campaign index.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const docPath = join(repoRoot, "docs", "adapter-surface.md");

/** Every `readonly <slot>` inside a `declare module "@o3co/auth-provider-core"` block. */
function declaredSlots(): string[] {
	const slots: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir)) {
			// Test files declare throwaway slots (`slotA`, `mySlot`) to exercise
			// the manifest types; those are not surface.
			if (entry === "node_modules" || entry === "dist" || entry === "__tests__") continue;
			const full = join(dir, entry);
			if (statSync(full).isDirectory()) {
				walk(full);
				continue;
			}
			if (!entry.endsWith(".mts")) continue;
			const source = readFileSync(full, "utf8");
			for (const block of source.matchAll(
				/declare module "@o3co\/auth-provider-core"\s*\{([\s\S]*?)\n\}/g,
			)) {
				for (const slot of (block[1] ?? "").matchAll(/readonly (\w+)\??\s*:/g)) {
					const name = slot[1];
					if (name !== undefined) slots.push(name);
				}
			}
		}
	};
	walk(join(repoRoot, "packages"));
	return [...new Set(slots)].sort();
}

const doc = readFileSync(docPath, "utf8");

/**
 * Slot names the doc lists.
 *
 * Matched on the five-column slot-table row shape, not on "first cell in
 * backticks": the lifecycle section carries a two-column table of conformance
 * suites whose first column is a *port type* (`AccessTokenDenylist`), and
 * counting those would have the guard demanding a ComponentMap slot for every
 * interface name in the document.
 */
function documentedSlots(): string[] {
	return [
		...new Set(
			[...doc.matchAll(/^\| `(\w+)` \| `[^`]+` \| (?:required|optional) \| `[^`]+` \|/gm)].map(
				(m) => m[1] as string,
			),
		),
	].sort();
}

/** Repository-relative paths the doc cites in backticks. */
function citedPaths(): string[] {
	return [
		...new Set(
			[...doc.matchAll(/`((?:packages|docs)\/[\w./-]+\.mts)`/g)].map((m) => m[1] as string),
		),
	];
}

describe("adapter-surface inventory (#305)", () => {
	const declared = declaredSlots();
	const documented = documentedSlots();

	it("finds slots at all — the scan is not vacuously passing", () => {
		// A guard whose scan silently returns nothing reports success forever.
		expect(declared.length).toBeGreaterThan(20);
		expect(declared).toContain("keyStore");
		expect(documented.length).toBeGreaterThan(20);
	});

	it("documents every slot that is declared", () => {
		const undocumented = declared.filter((s) => !documented.includes(s));
		expect(undocumented).toEqual([]);
	});

	it("declares every slot that is documented", () => {
		const orphaned = documented.filter((s) => !declared.includes(s));
		expect(orphaned).toEqual([]);
	});

	it("cites only files that exist", () => {
		// The doc points implementers at conformance suites by path. A path that
		// does not resolve sends them looking for something that was moved or
		// never landed.
		const missing = citedPaths().filter((p) => !existsSync(join(repoRoot, p)));
		expect(missing).toEqual([]);
	});

	it("cites the conformance suites it promises", () => {
		// The lifecycle section's whole claim is that an out-of-tree adapter can
		// prove itself. If the table is empty the claim is decoration.
		expect(citedPaths().filter((p) => p.includes("contract")).length).toBeGreaterThan(3);
	});
});
