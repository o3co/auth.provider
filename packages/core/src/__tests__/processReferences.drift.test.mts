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
 * processReferences.drift.test.mts — a comment in product code states what
 * holds now, not how it came to be (AGENTS.md, "Source comments"). An issue
 * or pull request number, a plan's phase, or the label of a review finding or
 * of an item in a design record is history: it belongs in the commit, the
 * issue or the CHANGELOG, and it sends the reader out of the file to learn
 * what the comment means.
 *
 * What it reads, with TypeScript's parser, is every comment in every product
 * source under a package's `src/`: a source outside `__tests__/` and not a
 * `*.test.*` or `*.spec.*` file, which ships. A URL is blanked out before a
 * comment is read, so a link's fragment is not a reference, and neither is a
 * specification's section (`RFC 6749 §4.1.3`).
 *
 * What counts as a reference (`REFERENCE_PATTERNS`):
 *
 * - an issue or pull request number, with its repository when it names one:
 *   `#728`, `auth.proxy#90`;
 * - a pull request by its place in a series: `PR6`;
 * - a plan's phase: `Phase G`, `Phase 9`;
 * - a label made of capitals, an optional digit, a hyphen, then a number or a
 *   Greek letter: `D-6`, `CP-18`, `P1-1`, `AS-M1`, `A2-β`, also when a word is
 *   joined to it (`pre-D-6`). The names of algorithms, encodings and address
 *   blocks share the form and are not references (`STANDARD_NAMES`):
 *   `SHA-256`, `UTF-8`, `P-256`, `ML-DSA-44`, `TEST-NET-1`.
 *
 * The references product code carries are listed, per file and per
 * reference, in `processReferences.baseline.json`. The list may only shrink:
 * a reference beyond it fails, and so does a count the code no longer
 * reaches, until the list is lowered to it.
 *
 * What it does not read is left to review: a bare capital and number (`D7`,
 * `B3`), which names a design record's decision as often as it names nothing
 * at all (`S3`, `P1`); the version a change landed in; and history told in
 * prose.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

const BASELINE = fileURLToPath(new URL("./processReferences.baseline.json", import.meta.url));

/**
 * Each kind of reference, read over a comment whose URLs are blanked out. The
 * match is the reference, unless the pattern names it `ref`; a label's match
 * is the whole hyphenated name it ends (`name`), so that `ML-DSA-44` is read
 * as one name and `pre-D-6` as a word joined to `D-6`.
 */
const REFERENCE_PATTERNS: readonly RegExp[] = [
	// An issue or pull request number, with the repository it is in when it
	// names one (`auth.proxy#90`, `o3co/auth#48`). A bare number follows no
	// letter or digit (`PKCS#11` is a standard's name) and no `&` (`&#128;` is
	// a character reference).
	/(?:[\w-]+(?:[./][\w-]+)+|(?<![\w&#]))#\d{2,}\b/gu,
	// A pull request by its place in a series.
	/\bPR ?\d+\b/gu,
	// A plan's phase.
	/\bPhase [A-Z0-9]{1,2}\b/gu,
	// A label: `D-6`, `P1-1`, `AS-M1`, `A2-β`.
	/(?<![\w-])(?<name>(?:[A-Za-z]+-)*(?<ref>[A-Z]{1,4}\d?-(?:[A-Z]?\d{1,3}[a-z]?\b|[α-ω](?![\p{L}\p{N}]))))/gu,
];

/** Algorithms, encodings and address blocks whose names have a label's form. */
const STANDARD_NAMES =
	/^(?:SHA-(?:1|224|256|384|512)|UTF-(?:8|16|32)|AES-(?:128|192|256)|P-(?:256|384|521)|ML-(?:DSA|KEM)-\d+|TEST-NET-[1-3]|ECMA-262)$/u;

/** The references in `comment`, each with its offset, in the order they appear. */
function referencesIn(comment: string): { reference: string; offset: number }[] {
	const text = comment.replace(/https?:\/\/\S+/gu, (url) => " ".repeat(url.length));
	const found: { reference: string; offset: number }[] = [];
	for (const pattern of REFERENCE_PATTERNS) {
		for (const match of text.matchAll(pattern)) {
			const reference = match.groups?.ref ?? match[0];
			const name = match.groups?.name ?? match[0];
			if (STANDARD_NAMES.test(name) || STANDARD_NAMES.test(reference)) continue;
			found.push({ reference, offset: match.index + match[0].lastIndexOf(reference) });
		}
	}
	return found.sort((a, b) => a.offset - b.offset);
}

/**
 * Every comment in `text`, each once, with where it starts. A JSDoc node's
 * children lie inside its comment, so they are not read for comments of
 * their own.
 */
function commentsIn(file: string, text: string): { pos: number; text: string }[] {
	const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
	const found = new Map<number, string>();
	const collect = (ranges: readonly ts.CommentRange[] | undefined): void => {
		for (const range of ranges ?? []) found.set(range.pos, text.slice(range.pos, range.end));
	};
	const visit = (node: ts.Node): void => {
		if (node.kind >= ts.SyntaxKind.FirstJSDocNode && node.kind <= ts.SyntaxKind.LastJSDocNode) {
			return;
		}
		collect(ts.getLeadingCommentRanges(text, node.getFullStart()));
		collect(ts.getTrailingCommentRanges(text, node.getEnd()));
		for (const child of node.getChildren(source)) visit(child);
	};
	visit(source);
	return [...found].map(([pos, comment]) => ({ pos, text: comment }));
}

/** Every product source under a package's `src/`, relative to the repository. */
function productSources(): string[] {
	const files: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(join(repoRoot, dir), { withFileTypes: true })) {
			const path = `${dir}/${entry.name}`;
			if (entry.isDirectory()) {
				if (entry.name !== "__tests__") walk(path);
			} else if (/\.[cm]?[jt]sx?$/u.test(entry.name) && !/\.(?:test|spec)\./u.test(entry.name)) {
				files.push(path);
			}
		}
	};
	for (const entry of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
		const src = `packages/${entry.name}/src`;
		if (entry.isDirectory() && existsSync(join(repoRoot, src))) walk(src);
	}
	return files.sort();
}

/** A reference, where it is. */
interface Found {
	readonly file: string;
	readonly line: number;
	readonly reference: string;
}

/** How many times each file carries each reference. */
type Counts = Record<string, Record<string, number>>;

const FOUND: readonly Found[] = productSources().flatMap((file) => {
	const text = readFileSync(join(repoRoot, file), "utf8");
	const lineOf = (pos: number): number => text.slice(0, pos).split("\n").length;
	return commentsIn(file, text).flatMap((comment) =>
		referencesIn(comment.text).map(({ reference, offset }) => ({
			file,
			line: lineOf(comment.pos + offset),
			reference,
		})),
	);
});

function countsOf(found: readonly Found[]): Counts {
	const counts: Counts = {};
	for (const { file, reference } of found) {
		const inFile = counts[file] ?? {};
		inFile[reference] = (inFile[reference] ?? 0) + 1;
		counts[file] = inFile;
	}
	return counts;
}

const COUNTS = countsOf(FOUND);
const ALLOWED: Counts = JSON.parse(readFileSync(BASELINE, "utf8"));

describe("process references in product-code comments", () => {
	it("reads each kind of reference, in the order it appears", () => {
		const comment =
			"// Since #728 (PR6, PR #185, auth.proxy#90, o3co/auth#48) in Phase G, D-6, DSA-44, CP-18, P1-1, AS-M1 and A2-β §4.1 hold.";
		expect(referencesIn(comment).map(({ reference }) => reference)).toEqual([
			"#728",
			"PR6",
			"#185",
			"auth.proxy#90",
			"o3co/auth#48",
			"Phase G",
			"D-6",
			"DSA-44",
			"CP-18",
			"P1-1",
			"AS-M1",
			"A2-β",
		]);
	});

	it("reads a reference that a word is joined to by a hyphen or a slash", () => {
		const comment = "// pre-#292 and #266/#307; pre-D-6, Post-SF-3 and TODO-F-4.";
		expect(referencesIn(comment).map(({ reference }) => reference)).toEqual([
			"#292",
			"#266",
			"#307",
			"D-6",
			"SF-3",
			"F-4",
		]);
	});

	it("reads no link, specification section, algorithm name or character reference as one", () => {
		const comment = [
			"// RFC 6749 §4.1.3 and RFC 9207 §2.4;",
			"// https://github.com/o3co/auth.provider/issues/728#issuecomment-5881889891;",
			"// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1;",
			"// SHA-256, SHA-1, UTF-8, UTF-16, AES-256, P-256, ML-DSA-44, ML-KEM-768, HMAC-SHA-256, ECMA-262;",
			"// TEST-NET-1 (RFC 5737), PKCS#11 and PKCS#12;",
			"// &#128; in the two phases of a parse.",
		].join("\n");
		expect(referencesIn(comment)).toEqual([]);
	});

	it("finds the comments of a file once each, and none inside a string or a template", () => {
		const text = [
			"/** Header #11. */",
			'const a = "// not #12"; // after #13',
			// biome-ignore lint/suspicious/noTemplateCurlyInString: the sample is source text that holds a template literal.
			"const b = `/* not #14 */ ${a /* inside #15 */}`;",
			"/**",
			" * @param x — see #16",
			" */",
			"function f(x: number): number {",
			"\treturn x; /* #17 */",
			"}",
			"// last #18",
		].join("\n");
		const references = commentsIn("sample.mts", text).flatMap((comment) =>
			referencesIn(comment.text).map(({ reference }) => reference),
		);
		expect(references.sort()).toEqual(["#11", "#13", "#15", "#16", "#17", "#18"]);
	});

	it("finds no reference beyond the ones listed for its file", () => {
		const beyond = FOUND.filter(
			({ file, reference }) => (COUNTS[file]?.[reference] ?? 0) > (ALLOWED[file]?.[reference] ?? 0),
		).map(
			({ file, line, reference }) =>
				`${file}:${line} ${reference} — ${ALLOWED[file]?.[reference] ?? 0} listed, ${COUNTS[file]?.[reference]} found`,
		);
		expect(
			beyond,
			"state the rule the comment keeps, without the reference; history belongs in the commit, the issue or the CHANGELOG",
		).toEqual([]);
	});

	it("lists no reference the code no longer carries", () => {
		const gone = Object.entries(ALLOWED).flatMap(([file, listed]) =>
			Object.entries(listed)
				.filter(([reference, count]) => (COUNTS[file]?.[reference] ?? 0) < count)
				.map(
					([reference, count]) =>
						`${file} ${reference} — ${count} listed, ${COUNTS[file]?.[reference] ?? 0} found`,
				),
		);
		expect(gone, `lower each count in ${BASELINE} to the one found, and drop a zero`).toEqual([]);
	});
});
