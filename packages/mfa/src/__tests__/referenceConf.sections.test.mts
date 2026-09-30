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
 * The package's `config/reference.conf`: the modules that read it
 * declare it as their section's reference, and it holds only their
 * sections, which their section schemas parse without losing a path —
 * core's `packageReferenceProblems`, the check every package with defaults
 * runs over its own file. A variable it still binds at the TOTP factor's old
 * path is a tombstone: no default, and a name that changed with the path.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	assertRelocationTombstone,
	packageReferenceProblems,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { mfaModule } from "#/module.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The TOTP factor's old path, and its section's path now. */
const OLD_PATH = "mfa.factors.totp";
const NEW_PATH = "mfa-totp-factor";

const MARKER = "__MFA_REFERENCE_MARKER__";

/** Every path in `tree` whose value is the marker. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	if (typeof tree === "object" && tree !== null && !Array.isArray(tree)) {
		return Object.entries(tree).flatMap(([key, value]) =>
			markedPaths(value, prefix === "" ? key : `${prefix}.${key}`),
		);
	}
	return tree === MARKER ? [prefix] : [];
}

/** The value at a dotted path, or `undefined`. */
function valueAt(tree: unknown, path: string): unknown {
	let cursor: unknown = tree;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null || !Object.hasOwn(cursor, key)) {
			return undefined;
		}
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/** Each variable the file binds at or under the old path, and the path that key moved to. */
function tombstones(): { readonly variable: string; readonly to: string }[] {
	const file = fileURLToPath(REFERENCE);
	const variables = [
		...new Set(
			[...readFileSync(file, "utf8").matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) =>
				String(match[1]),
			),
		),
	];
	return variables.flatMap((variable) =>
		markedPaths(parseFile(file, { env: { [variable]: MARKER } }).toObject())
			.filter((path) => path.startsWith(`${OLD_PATH}.`))
			.map((path) => ({ variable, to: `${NEW_PATH}${path.slice(OLD_PATH.length)}` })),
	);
}

describe("the package's config/reference.conf", () => {
	const modules = [mfaModule(), mfaTotpFactorModule];

	it("is read at each module's name: mfa, and mfa-totp-factor", () => {
		expect(modules.map((module) => module.section?.at)).toEqual([undefined, undefined]);
		expect(modules.map((module) => module.name)).toEqual(["mfa", NEW_PATH]);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		const read = (path: string): unknown => parseFile(path, { env: {} }).toObject();
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([]);
	});

	it("binds a variable at the TOTP factor's old path only as a tombstone: no default, and a name that changed with the path", () => {
		const found = tombstones();
		expect(found).toEqual([
			{ variable: "MFA_TOTP_ENABLED", to: `${NEW_PATH}.enabled` },
			{ variable: "MFA_TOTP_ISSUER", to: `${NEW_PATH}.issuer` },
		]);
		for (const tombstone of found) assertRelocationTombstone(tombstone);
		expect(valueAt(parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject(), OLD_PATH)).toEqual(
			{},
		);
	});
});
