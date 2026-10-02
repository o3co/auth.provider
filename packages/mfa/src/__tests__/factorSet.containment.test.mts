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
 * The factor set's store generation stays in `factorSet.mts`: no other
 * module of the package reads a versioned set, writes a conditional member,
 * or names a generation. Enrollment, recovery codes, regeneration,
 * management and the reset are handed records and outcomes. The testing
 * entry seeds a store as a writer of the set would, and is no module of the
 * running package.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(import.meta.dirname, "..");

/** What only the factor set's writer may name. */
const GENERATION_WORDS =
	/\b(?:listVersioned|createIf|removeIf|StoreGeneration|storeGeneration|isStoreGeneration|newStoreGeneration|VersionedSet|readMfaFactorSet|readVersionedSet|readConditional\w*)\b/;

/** The package's own source files, relative to `src`, tests left out. */
function sourceFiles(): string[] {
	return readdirSync(SRC, { recursive: true, encoding: "utf8" })
		.filter((path) => path.endsWith(".mts") && !path.split(/[\\/]/).includes("__tests__"))
		.sort();
}

describe("the factor set's store generation", () => {
	it("is named by factorSet.mts alone among the package's modules, the testing entry's seeding apart", () => {
		const naming = sourceFiles().filter((path) =>
			GENERATION_WORDS.test(readFileSync(join(SRC, path), "utf8")),
		);
		expect(naming.map((path) => relative(".", path).replaceAll("\\", "/"))).toEqual([
			"factorSet.mts",
			"testing/index.mts",
		]);
	});
});
