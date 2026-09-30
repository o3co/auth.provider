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
 * The package's `config/reference.conf`: it holds the section of the module
 * that keeps MFA factors in the Store and nothing else, which the section's
 * schema parses without losing a path — core's `packageReferenceProblems`,
 * run over a module declaring the section as the Store adapter's will. Each
 * URL is bound to the variable named after its path, and has no default.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { FOUNDATION_MFA_FACTOR_STORE_SECTION } from "#/mfa/section.mjs";
import { fixtureModule } from "./fixtureModule.mjs";

const REFERENCE = new URL("../../../config/reference.conf", import.meta.url);

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

/** Each variable the file substitutes, set to a marker of its own name, and the path it lands on. */
function bindings(): string[] {
	const path = fileURLToPath(REFERENCE);
	const text = readFileSync(path, "utf8");
	const names = [...text.matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) => String(match[1]));
	const tree = read(path, Object.fromEntries(names.map((name) => [name, `marker:${name}`])));
	const found: string[] = [];
	const walk = (value: unknown, prefix: string): void => {
		if (typeof value === "object" && value !== null) {
			for (const [key, child] of Object.entries(value)) {
				walk(child, prefix === "" ? key : `${prefix}.${key}`);
			}
		} else if (typeof value === "string" && value.startsWith("marker:")) {
			found.push(`${value.slice("marker:".length)} at ${prefix}`);
		}
	};
	walk(tree, "");
	return found.sort();
}

describe("the package's reference.conf", () => {
	it("holds only the section of the module that declares it, which its schema parses without losing a path", () => {
		expect(
			packageReferenceProblems({ reference: REFERENCE, modules: [fixtureModule], read }),
		).toEqual([]);
	});

	it("binds each URL to the variable named after its path", () => {
		expect(bindings()).toEqual([
			`FOUNDATION_MFA_FACTOR_STORE_CREATE_URL at ${FOUNDATION_MFA_FACTOR_STORE_SECTION}.createUrl`,
			`FOUNDATION_MFA_FACTOR_STORE_DELETE_URL at ${FOUNDATION_MFA_FACTOR_STORE_SECTION}.deleteUrl`,
			`FOUNDATION_MFA_FACTOR_STORE_LIST_URL at ${FOUNDATION_MFA_FACTOR_STORE_SECTION}.listUrl`,
			`FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL at ${FOUNDATION_MFA_FACTOR_STORE_SECTION}.updateUrl`,
		]);
	});

	it("gives no URL a default", () => {
		expect(read(fileURLToPath(REFERENCE), {})).toEqual({
			[FOUNDATION_MFA_FACTOR_STORE_SECTION]: {},
		});
	});
});
