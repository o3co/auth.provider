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

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	callersOf,
	isPackageSpecifier,
	prologueDeclarations,
	prologueImports,
} from "./contract-parity.helpers.mjs";

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
		const imports = prologueImports(
			COPY,
			readFileSync(COPY, "utf8").indexOf("export interface FederationGrantStoreContractFactory"),
		);
		expect(imports).toContain("@o3co/auth-provider-core");
		// A copy imports packages only. Core's `#/` alias does not resolve from
		// here, and any path — relative, absolute, `file:` — would reach into
		// core's source rather than what the package publishes.
		for (const specifier of imports) {
			expect(isPackageSpecifier(specifier), specifier).toBe(true);
		}
	});

	it("has nothing but comments and imports above that line, in either copy", () => {
		// Comparing the bodies leaves the prologue out, and the reviewer showed
		// what fits there: `import { it as rawIt } from "vitest"; const it =
		// rawIt.skip;` leaves the parity test green and skips all 123 cases. A
		// shadowed `expect`, a rebound `describe` or a stale constant do the
		// same. So the prologue may declare nothing at all.
		// Read as a syntax tree, so a declaration sharing a line with an import
		// is still a declaration (#626).
		for (const path of [CORE, COPY]) {
			const from = readFileSync(path, "utf8").indexOf(
				"export interface FederationGrantStoreContractFactory",
			);
			expect(from, `${path}: the suite's first export`).toBeGreaterThan(0);
			expect(prologueDeclarations(path, from), path).toEqual([]);
		}
	});

	it("is run by something: a copy nothing calls cannot fail", () => {
		// A call in the syntax tree, so a commented-out call does not count.
		expect(callersOf(here, "runFederationGrantStoreContract")).toContain(
			"federation-grant-store.integration.test.mts",
		);
	});
});
