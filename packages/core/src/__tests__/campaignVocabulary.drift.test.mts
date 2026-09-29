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
 * Checks `docs/design-campaign-index.md`, which gives the meanings of the
 * campaign identifiers (`IH-16`, `D-6`, `A2-β §5.1`, …) that shipped source
 * and READMEs cite; their defining documents were never committed.
 *
 * 1. Every campaign ID cited in shipped source or a README resolves in the
 *    index, or is on the exclusion list below.
 * 2. Every ID the index carries is still cited somewhere in the repo.
 *
 * Scanned families: hyphenated series (`IH-…`, `D-…`, …), A-spec documents
 * (only before `§` or `Amendment`; bare `A1` would false-positive on base64
 * and identifiers), and the bare S-series (`S1`–`S15`; the digit boundary
 * keeps `S256`/`S512` out). Wave/Phase tags and the webauthn T-series are
 * indexed but not checked: `Wave`/`Phase` is prose, and a bare `T<n>`
 * collides with generic type parameters.
 *
 * CHANGELOGs count as occurrence sites (direction 2) but never require an
 * index entry (direction 1).
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");
const indexPath = join(repoRoot, "docs/design-campaign-index.md");

/**
 * Identifiers deliberately absent from the index, by owner decision: their
 * meaning did not survive the sessions that coined them. They are session
 * development codes, not durable vocabulary; do not cite them as rationale.
 */
const EXCLUDED_IDS = new Set([
	"AS-5",
	"AS-6",
	"SC-1",
	"SC-2",
	"S10",
	"S15",
	"OR-3",
	"IH-18",
	"D-7",
	"CP-3",
	"CP-4",
	"CP-5",
	"CP-8",
	"CP-9",
	"CP-19",
]);

const HYPHENATED = /\b(?:IH|OR|SF|MIN|PB|AS|CP|CR|CC|TS|SC|TD|D|F)-\d+\b/g;
/**
 * Citations write A-docs as `A2-β §5.1` / `A2-γ Amendment 3`, so the strict
 * form requires the section marker. The index names the docs in headings
 * (`### A2-β — …`), so extraction from the index, and the direction-2 sweep
 * compared against it, use the loose form.
 */
const A_DOC_STRICT = /\bA[1-7](?:-[αβγ])?(?=\s+(?:§|Amendment))/g;
// (?!\d) instead of a trailing \b: JS \b is ASCII-only, so after a Greek
// letter it would only match before a word character and `A2-β —` would
// truncate to `A2`. The lookahead just has to keep `A25` from matching `A2`.
const A_DOC_LOOSE = /\bA[1-7](?:-[αβγ])?(?!\d)/g;
const BARE_S = /\bS(?:1[0-5]|[1-9])\b/g;

function idsIn(text: string, aDoc: RegExp = A_DOC_STRICT): Set<string> {
	const ids = new Set<string>();
	for (const re of [HYPHENATED, aDoc, BARE_S]) {
		for (const m of text.matchAll(re)) ids.add(m[0]);
	}
	return ids;
}

function walk(dir: string, keep: (name: string, path: string) => boolean, out: string[]): void {
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git") continue;
		const path = join(dir, entry.name);
		if (entry.isDirectory()) walk(path, keep, out);
		else if (keep(entry.name, path)) out.push(path);
	}
}

/** Direction-1 scope: shipped .mts (tests excluded) + READMEs. Never CHANGELOGs or docs/. */
function citationSites(): string[] {
	const files: string[] = [];
	for (const base of ["packages", "templates/standalone/src", "create-app"]) {
		walk(
			join(repoRoot, base),
			(name, path) =>
				(name.endsWith(".mts") && path.includes("/src/") && !path.includes("/__tests__/")) ||
				name === "README.md" ||
				name === "README.ja.md",
			files,
		);
	}
	files.push(join(repoRoot, "README.md"), join(repoRoot, "README.ja.md"));
	return files;
}

/** Direction-2 scope: anywhere in the repo an ID can legitimately live on. */
function occurrenceSites(): string[] {
	const files: string[] = [];
	walk(
		repoRoot,
		(name, path) =>
			!path.includes("/docs/design-campaign-index.md") &&
			(name.endsWith(".mts") ||
				name.endsWith(".md") ||
				name.endsWith(".conf") ||
				name.endsWith(".yml") ||
				name.endsWith(".yaml")),
		files,
	);
	return files;
}

describe("design-campaign provenance index", () => {
	const indexText = readFileSync(indexPath, "utf8");
	const indexed = idsIn(indexText, A_DOC_LOOSE);

	const cited = new Set<string>();
	for (const file of citationSites()) {
		let text: string;
		try {
			text = readFileSync(file, "utf8");
		} catch {
			continue;
		}
		for (const id of idsIn(text)) cited.add(id);
	}

	it("finds a plausible citation surface (sanity: the guard is not vacuous)", () => {
		expect(cited.size).toBeGreaterThan(0);
		expect(indexed.size).toBeGreaterThan(50);
	});

	it("resolves every cited campaign ID in the index", () => {
		const unresolved = [...cited].filter((id) => !indexed.has(id) && !EXCLUDED_IDS.has(id)).sort();
		expect(unresolved, "cited in shipped source/READMEs but absent from the index").toEqual([]);
	});

	it("carries no ID nothing cites any more", () => {
		const everywhere = new Set<string>();
		for (const file of occurrenceSites()) {
			let text: string;
			try {
				text = readFileSync(file, "utf8");
			} catch {
				continue;
			}
			for (const id of idsIn(text, A_DOC_LOOSE)) everywhere.add(id);
		}
		const dead = [...indexed].filter((id) => !everywhere.has(id)).sort();
		expect(dead, "indexed but no citation site found anywhere").toEqual([]);
	});

	it("keeps the excluded list excluded — an excluded ID gaining an index entry is a decision reversal", () => {
		const contradictions = [...EXCLUDED_IDS].filter((id) => indexed.has(id)).sort();
		expect(contradictions, "excluded by the #386 owner decision yet present in the index").toEqual(
			[],
		);
	});
});
