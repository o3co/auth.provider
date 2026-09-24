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

// The two copies of the `UserSessionStore` contract suite are the same suite
// (#626).
//
// A contract file cannot be imported across a package boundary, so the Redis
// package runs a copy. This one had drifted: core's gained the #481 `amr`
// round-trip and the copy never did, so the Redis store could lose `amr` on
// its way back and every Redis test passed. The federation grant suites are
// held the same way, by `federation-grant-contract-parity.test.mts`.
//
// So the only difference allowed is the import block. When the core suite
// changes, copy it again and re-run.

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
const CORE = join(here, "../../core/src/user-sessions/__tests__/userSessionStore.contract.mts");
const COPY = join(here, "userSessionStore.contract.mts");
const FIRST_EXPORT = "export type UserSessionStoreContractFactory";

/** Everything from the suite's first export on: what the two may not differ in. */
const body = (path: string): string => {
	const text = readFileSync(path, "utf8");
	const from = text.indexOf(FIRST_EXPORT);
	expect(from, `${path}: the suite's first export`).toBeGreaterThan(0);
	return text.slice(from);
};

describe("the UserSessionStore contract suite, in both copies", () => {
	it("is the same suite: only the import block may differ", () => {
		const coreLines = body(CORE).split("\n");
		const copyLines = body(COPY).split("\n");
		// Line by line rather than whole-file, so a failure says which line.
		for (let i = 0; i < Math.max(coreLines.length, copyLines.length); i += 1) {
			expect(
				copyLines[i],
				`line ${i + 1} of the suite body differs; copy ` +
					"packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts again",
			).toBe(coreLines[i]);
		}
	});

	it("imports the port from the package rather than from core's source", () => {
		const imports = prologueImports(COPY, readFileSync(COPY, "utf8").indexOf(FIRST_EXPORT));
		expect(imports).toContain("@o3co/auth-provider-core");
		// A copy imports packages only. Core's `#/` alias does not resolve from
		// here, and any path — relative, absolute, `file:` — would reach into
		// core's source rather than what the package publishes.
		for (const specifier of imports) {
			expect(isPackageSpecifier(specifier), specifier).toBe(true);
		}
	});

	it("has nothing but comments and imports above that line, in either copy", () => {
		// A declaration there — a shadowed `it`, a rebound `expect` — would change
		// what the suite runs while the bodies still compare equal.
		// Read as a syntax tree, so a declaration sharing a line with an import
		// is still a declaration (#626).
		for (const path of [CORE, COPY]) {
			const from = readFileSync(path, "utf8").indexOf(FIRST_EXPORT);
			expect(from, `${path}: the suite's first export`).toBeGreaterThan(0);
			expect(prologueDeclarations(path, from), path).toEqual([]);
		}
	});

	it("is run by something: a copy nothing calls cannot fail", () => {
		// A call in the syntax tree, so a commented-out call does not count.
		expect(callersOf(here, "runUserSessionStoreContract")).toContain(
			"redis.userSessionStore.test.mts",
		);
	});
});
