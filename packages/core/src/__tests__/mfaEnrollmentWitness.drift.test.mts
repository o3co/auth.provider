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
 * The MFA enrollment witness has one reading (the MFA ADR's D12):
 * `readMfaEnrollmentWitness`, which answers a value that is neither a boolean
 * nor absent as `malformed` — `503`, never a first binding. A second reading
 * written as `user.mfaEnrolled === true` would read a Store's `1` or `"true"`
 * as "not enrolled", which is the downgrade D12 exists to prevent, and it
 * would look harmless in a diff.
 *
 * So no product file in any package reads `mfaEnrolled` but the reader
 * itself: a property access (`user.mfaEnrolled`, `user?.mfaEnrolled`), an
 * element access by the literal name, or a destructuring binding. Read with
 * TypeScript's parser, so a comment or a string that names the field is not a
 * read, and the declaration on `User` is not one either. Tests are left out:
 * they assert on the raw value on purpose.
 */

import { type Dirent, existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

/** The repository root, from `packages/core/src/__tests__`. */
const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));

/** The one file that may read the field: the reader. */
const ALLOWED: ReadonlySet<string> = new Set(["packages/core/src/repositories/UserRepository.mts"]);

/** The 1-based lines of `source` that read `mfaEnrolled`. */
function witnessReads(source: string): number[] {
	const file = ts.createSourceFile("scan.mts", source, ts.ScriptTarget.Latest, true);
	const lines: number[] = [];
	const named = (node: ts.Node | undefined): boolean =>
		node !== undefined &&
		(ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
		node.text === "mfaEnrolled";
	const visit = (node: ts.Node): void => {
		const reads =
			(ts.isPropertyAccessExpression(node) && node.name.text === "mfaEnrolled") ||
			(ts.isElementAccessExpression(node) && named(node.argumentExpression)) ||
			(ts.isBindingElement(node) &&
				(node.propertyName !== undefined ? named(node.propertyName) : named(node.name)));
		if (reads) lines.push(file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1);
		ts.forEachChild(node, visit);
	};
	visit(file);
	return lines;
}

/** Every product source file under `packages/<name>/src`, relative to the root, `/`-separated. */
function productSources(): string[] {
	const found: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir, { withFileTypes: true }) as Dirent[]) {
			if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "__tests__") {
				continue;
			}
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				walk(path);
			} else if (
				/\.m?ts$/.test(entry.name) &&
				!/\.d\.m?ts$/.test(entry.name) &&
				!/\.test\.m?ts$/.test(entry.name)
			) {
				found.push(relative(repoRoot, path).split(sep).join("/"));
			}
		}
	};
	for (const pkg of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
		const src = join(repoRoot, "packages", pkg.name, "src");
		if (pkg.isDirectory() && existsSync(src)) walk(src);
	}
	return found.sort();
}

describe("the MFA enrollment witness has one reading (D12)", () => {
	it("is read by no product file but readMfaEnrollmentWitness's", () => {
		const offenders = productSources()
			.filter((file) => !ALLOWED.has(file))
			.flatMap((file) =>
				witnessReads(readFileSync(join(repoRoot, file), "utf8")).map((line) => `${file}:${line}`),
			);
		expect(offenders).toEqual([]);
	});

	it("sees the reader's own read, so the scan is not vacuous", () => {
		const [reader] = [...ALLOWED];
		expect(productSources()).toContain(reader);
		expect(witnessReads(readFileSync(join(repoRoot, reader as string), "utf8"))).toHaveLength(1);
		// The declaration on `User` names the field and reads nothing.
		expect(
			witnessReads(
				readFileSync(join(repoRoot, "packages/core/src/repositories/types.mts"), "utf8"),
			),
		).toEqual([]);
	});

	it("flags every way of reading the field, and nothing that only names it", () => {
		for (const read of [
			"if (user.mfaEnrolled === true) bind();",
			"const w = snapshot?.mfaEnrolled;",
			'const w = user["mfaEnrolled"];',
			"const { mfaEnrolled } = user;",
			"const { mfaEnrolled: enrolled } = user;",
			"const f = ({ mfaEnrolled }: User) => mfaEnrolled;",
		]) {
			expect(witnessReads(read), read).toHaveLength(1);
		}
		for (const notARead of [
			"// reads User.mfaEnrolled through the reader",
			"/* user.mfaEnrolled === true */",
			'const message = "user.mfaEnrolled is malformed";',
			"interface U { readonly mfaEnrolled?: boolean }",
			"const user = { mfaEnrolled: true };",
			"readMfaEnrollmentWitness(user);",
		]) {
			expect(witnessReads(notARead), notARead).toEqual([]);
		}
	});
});
