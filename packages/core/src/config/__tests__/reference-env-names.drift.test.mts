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
 * #728 B9: an environment variable a package's defaults read is named after
 * the path it sets, in upper snake case, with no exception —
 * `oauth.dpop.nonce.ttl-seconds` is `OAUTH_DPOP_NONCE_TTL_SECONDS`, a list
 * element's index is a word of its own (`mfa.encryptionKeys.0.key` is
 * `MFA_ENCRYPTION_KEYS_0_KEY`), and a camelCase key splits at each capital.
 *
 * It reads every package's `config/reference.conf`: each `${?VAR}` (or
 * `${VAR}`) outside a comment is resolved alone, set to a marker, and the
 * paths the marker lands on are the paths the variable sets. A name that is
 * not the upper-snake-case form of each of its paths fails, unless it is on
 * `TODAY`: the names that predate the rule, which the move pull requests
 * rename. That list may only shrink — an entry that no longer holds fails
 * until it is removed.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";

const PACKAGES = fileURLToPath(new URL("../../../../", import.meta.url));

/** The names that predate the rule, as `<package>: <VAR> at <path>`; the move pull requests rename them. */
const TODAY: readonly string[] = [];

/** A path in upper snake case: each key split at its capitals and hyphens, the keys joined by `_`. */
const upperSnake = (path: string): string =>
	path
		.split(".")
		.map((key) =>
			key
				.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
				.replace(/-/g, "_")
				.toUpperCase(),
		)
		.join("_");

const MARKER = "__ENVIRONMENT_NAME_MARKER__";

/** Every path in `tree` whose value holds the marker; list elements by index. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	const join = (key: string) => (prefix === "" ? key : `${prefix}.${key}`);
	if (Array.isArray(tree))
		return tree.flatMap((value, index) => markedPaths(value, join(String(index))));
	if (typeof tree === "object" && tree !== null) {
		return Object.entries(tree).flatMap(([key, value]) => markedPaths(value, join(key)));
	}
	return typeof tree === "string" && tree.includes(MARKER) ? [prefix] : [];
}

/** The variables a file substitutes, outside its comments. */
function substitutedNames(text: string): string[] {
	const code = text
		.split("\n")
		.filter((line) => !/^\s*(#|\/\/)/.test(line))
		.join("\n");
	return [
		...new Set([...code.matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) => String(match[1]))),
	];
}

/** Every package's `config/reference.conf`, by package directory name. */
const REFERENCES: readonly (readonly [string, string])[] = readdirSync(PACKAGES, {
	withFileTypes: true,
})
	.filter((entry) => entry.isDirectory())
	.map((entry) => [entry.name, join(PACKAGES, entry.name, "config", "reference.conf")] as const)
	.filter(([, path]) => {
		try {
			readFileSync(path);
			return true;
		} catch {
			return false;
		}
	});

/** Every variable each reference substitutes, with each path it sets. */
const FOUND = REFERENCES.flatMap(([name, path]) =>
	substitutedNames(readFileSync(path, "utf8")).map((variable) => ({
		package: name,
		variable,
		paths: markedPaths(parseFile(path, { env: { [variable]: MARKER } }).toObject()),
	})),
);

/** Each variable at a path it is not the upper-snake-case form of, as `TODAY` writes it. */
const MISNAMED: readonly string[] = FOUND.flatMap(({ package: name, variable, paths }) =>
	paths
		.filter((path) => upperSnake(path) !== variable)
		.map((path) => `${name}: ${variable} at ${path}`),
);

describe("an environment variable is named after the path it sets (#728 B9)", () => {
	it("reads the packages' references (the guard is not vacuous)", () => {
		expect(REFERENCES.map(([name]) => name)).toEqual(
			expect.arrayContaining(["core", "mfa", "webauthn"]),
		);
		expect(FOUND.length).toBeGreaterThan(50);
	});

	it("resolves every variable a reference substitutes to a path it sets", () => {
		expect(
			FOUND.filter(({ paths }) => paths.length === 0).map(
				({ package: name, variable }) => `${name}: ${variable}`,
			),
		).toEqual([]);
	});

	it("spells the path in upper snake case: a key splits at its capitals and hyphens, a list index is a word", () => {
		expect(upperSnake("oauth.dpop.nonce.ttl-seconds")).toBe("OAUTH_DPOP_NONCE_TTL_SECONDS");
		expect(upperSnake("mfa.encryptionKeys.0.key")).toBe("MFA_ENCRYPTION_KEYS_0_KEY");
		expect(upperSnake("http.trustProxy")).toBe("HTTP_TRUST_PROXY");
	});

	it("names every variable after its path, but for the names that predate the rule", () => {
		expect(MISNAMED.filter((entry) => !TODAY.includes(entry))).toEqual([]);
	});

	it("keeps no name on the list that is now named after its path: the list only shrinks", () => {
		expect(TODAY.filter((entry) => !MISNAMED.includes(entry))).toEqual([]);
	});
});
