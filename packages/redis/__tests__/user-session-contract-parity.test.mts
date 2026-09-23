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

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

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
		const copy = readFileSync(COPY, "utf8");
		expect(copy).toContain('from "@o3co/auth-provider-core"');
		// Core's relative and `#/` paths do not resolve from this package; a copy
		// that kept one would fail to load rather than drift.
		const prologue = copy.slice(0, copy.indexOf(FIRST_EXPORT));
		expect(prologue).not.toContain('"#/');
		expect(prologue).not.toContain('"../types.mjs"');
	});

	it("has nothing but comments and imports above that line, in either copy", () => {
		// A declaration there — a shadowed `it`, a rebound `expect` — would change
		// what the suite runs while the bodies still compare equal.
		for (const path of [CORE, COPY]) {
			const text = readFileSync(path, "utf8");
			let inComment = false;
			let inImport = false;
			for (const [index, line] of text.slice(0, text.indexOf(FIRST_EXPORT)).split("\n").entries()) {
				const trimmed = line.trim();
				if (trimmed.length === 0) continue;
				if (inComment) {
					if (trimmed.includes("*/")) inComment = false;
					continue;
				}
				if (trimmed.startsWith("/*")) {
					if (!trimmed.includes("*/")) inComment = true;
					continue;
				}
				if (trimmed.startsWith("//")) continue;
				if (inImport) {
					if (trimmed.startsWith("}")) inImport = false;
					continue;
				}
				if (trimmed.startsWith("import ")) {
					if (trimmed.endsWith("{")) inImport = true;
					continue;
				}
				expect.fail(`${path}:${index + 1} is neither a comment nor an import: ${trimmed}`);
			}
		}
	});

	it("is run by something: a copy nothing calls cannot fail", () => {
		const callers = readdirSync(here).filter(
			(name) =>
				name.endsWith(".test.mts") &&
				readFileSync(join(here, name), "utf8").includes("runUserSessionStoreContract("),
		);
		expect(callers).toContain("redis.userSessionStore.test.mts");
	});
});
