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
 * The factor set's store generation and the factor store's unfenced writes
 * stay in `factorSet.mts`: no other module of the package reads a versioned
 * set, writes a conditional member, names a generation, or creates or
 * removes a record on the factor store itself. Enrollment, recovery codes,
 * regeneration, management and the reset are handed records and outcomes.
 * The testing entry seeds a store as a writer of the set would, outside any
 * lease, and is no module of the running package: no product module imports
 * it, nor anything under `__tests__`, so the scan below sees every module
 * the running package can load.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(import.meta.dirname, "..");

/** What only the factor set's writer may name (the testing entry's seeding apart). */
const GENERATION_WORDS =
	/\b(?:listVersioned|createIf|removeIf|StoreGeneration|storeGeneration|isStoreGeneration|newStoreGeneration|VersionedSet|readMfaFactorSet|readVersionedSet|readConditional\w*)\b/;

/** An unfenced write called on a factor store: only the factor set's writer and its reset make one. */
const STORE_WRITES = /\b\w*factorStore\??\s*\.\s*(?:create|remove|removeAllForSubject)\s*\(/i;

/** Every module specifier a file names: static and dynamic imports, re-exports, `require`. */
const SPECIFIERS = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)["']([^"']+)["']/g;

const SOURCE_EXTENSIONS = /\.(?:ts|cts|mts|js|cjs|mjs)$/;

const segments = (path: string): string[] => path.split(/[\\/]/);

/** The package's product modules, relative to `src` with `/` separators: everything outside `__tests__`. */
function productModules(): string[] {
	return readdirSync(SRC, { recursive: true, encoding: "utf8" })
		.filter((path) => SOURCE_EXTENSIONS.test(path) && !segments(path).includes("__tests__"))
		.map((path) => path.replaceAll("\\", "/"))
		.sort();
}

const read = (path: string): string => readFileSync(join(SRC, path), "utf8");

/** The product modules naming `pattern`. */
const naming = (pattern: RegExp): string[] =>
	productModules().filter((path) => pattern.test(read(path)));

/** `[module, specifier]` for every import of a product module whose specifier has a `segment` path segment. */
const importsThrough = (segment: string): [string, string][] =>
	productModules().flatMap((path) =>
		[...read(path).matchAll(SPECIFIERS)]
			.map((match) => match[1] ?? "")
			.filter((specifier) => segments(specifier).includes(segment))
			.map((specifier): [string, string] => [path, specifier]),
	);

describe("the factor set's store generation", () => {
	it("is named by factorSet.mts alone among the package's modules, the testing entry's seeding apart", () => {
		expect(naming(GENERATION_WORDS)).toEqual(["factorSet.mts", "testing/index.mts"]);
	});
});

describe("the factor store's unfenced writes", () => {
	it("create, remove and removeAllForSubject are called on a factor store by factorSet.mts alone", () => {
		expect(naming(STORE_WRITES)).toEqual(["factorSet.mts"]);
	});
});

describe("the modules the scan sees", () => {
	it("no product module imports anything under __tests__", () => {
		expect(importsThrough("__tests__")).toEqual([]);
	});

	it("no product module but the testing entry's own imports the testing entry", () => {
		expect(importsThrough("testing").filter(([path]) => segments(path)[0] !== "testing")).toEqual(
			[],
		);
	});
});
