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

// The two copies of the `FederationGrantStore` contract suite are the same
// suite (#593, D16).
//
// A contract file cannot be imported across a package boundary, so the Redis
// package runs a copy — and D16's whole claim is that the two adapters cannot
// disagree about what a grant is or which write wins. A copy of 2,500 lines
// drifts the week after it lands unless something checks it, and a copy that
// has drifted is worse than none: it reads as the same contract while
// asserting something else.
//
// So the only difference allowed is the import block, and this test is what
// says so. When the core suite changes, copy it again and re-run.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const CORE = join(here, "../../core/src/federation-grants/__tests__/store.contract.mts");
const COPY = join(here, "adapters.federation-grant-store.contract.mts");

/**
 * Everything from the first `export` on: the licence header, the file's own
 * docblock and the imports above it are what the two are allowed to differ
 * in, and nothing below it is.
 */
const body = (path: string): string => {
	const text = readFileSync(path, "utf8");
	const from = text.indexOf("export interface FederationGrantStoreContractFactory");
	expect(from, `${path}: the suite's first export`).toBeGreaterThan(0);
	return text.slice(from);
};

/** What is above that line, which comparing the bodies leaves out. */
const prologue = (path: string): string[] => {
	const text = readFileSync(path, "utf8");
	return text
		.slice(0, text.indexOf("export interface FederationGrantStoreContractFactory"))
		.split("\n");
};

describe("the FederationGrantStore contract suite, in both copies", () => {
	it("is the same suite: only the import block may differ", () => {
		const core = body(CORE);
		const copy = body(COPY);
		// Line by line rather than whole-file, so a failure says which line.
		const coreLines = core.split("\n");
		const copyLines = copy.split("\n");
		for (let i = 0; i < Math.max(coreLines.length, copyLines.length); i += 1) {
			expect(
				copyLines[i],
				`line ${i + 1} of the suite body differs; copy ` +
					"packages/core/src/federation-grants/__tests__/store.contract.mts again",
			).toBe(coreLines[i]);
		}
		expect(copyLines).toHaveLength(coreLines.length);
	});

	it("imports the port from the package rather than from core's source", () => {
		const copy = readFileSync(COPY, "utf8");
		expect(copy).toContain('from "@o3co/auth-provider-core"');
		// `#/` is core's own path alias; it does not resolve from this package,
		// and a copy that still used it would fail to load rather than drift.
		expect(copy.slice(0, copy.indexOf("export interface"))).not.toContain('"#/');
	});

	it("has nothing but comments and imports above that line, in either copy", () => {
		// Comparing the bodies leaves the prologue out, and the reviewer showed
		// what fits there: `import { it as rawIt } from "vitest"; const it =
		// rawIt.skip;` leaves the parity test green and skips all 123 cases. A
		// shadowed `expect`, a rebound `describe` or a stale constant do the
		// same. So the prologue may declare nothing at all.
		for (const path of [CORE, COPY]) {
			let inComment = false;
			let inImport = false;
			for (const [index, line] of prologue(path).entries()) {
				const text = line.trim();
				if (text.length === 0) continue;
				if (inComment) {
					if (text.includes("*/")) inComment = false;
					continue;
				}
				if (text.startsWith("/*")) {
					if (!text.includes("*/")) inComment = true;
					continue;
				}
				if (text.startsWith("//")) continue;
				if (inImport) {
					if (text.startsWith("}")) inImport = false;
					continue;
				}
				if (text.startsWith("import ")) {
					if (text.endsWith("{")) inImport = true;
					continue;
				}
				expect.fail(`${path}:${index + 1} is neither a comment nor an import: ${text}`);
			}
		}
	});

	it("is run by something: a copy nothing calls cannot fail", () => {
		const here = dirname(fileURLToPath(import.meta.url));
		const callers = readdirSync(here).filter(
			(name) =>
				name.endsWith(".test.mts") &&
				readFileSync(join(here, name), "utf8").includes("runFederationGrantStoreContract("),
		);
		expect(callers).toContain("federation-grant-store.integration.test.mts");
	});
});
