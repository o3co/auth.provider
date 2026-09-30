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
 * An environment variable a package's defaults read is named after the path
 * it sets, in upper snake case, with no exception: a list element's index is
 * a word of its own, and a camelCase key splits at each capital.
 *
 * It reads every package's `config/reference.conf` and the standalone
 * template's configuration layers (`templates/standalone/config/*.conf`):
 * each `${?VAR}` (or `${VAR}`) outside a comment is resolved alone, set to a
 * marker, and the paths the marker lands on are the paths the variable sets.
 * A capture of a renamed variable (`renamed-variables.<NAME>`) sets no
 * setting and is not held to the rule.
 *
 * The rule (`namingProblems`): a misnamed variable fails unless it is in
 * `LEGACY`, the names that predated the rule, whatever else a change renames.
 * `LEGACY` only loses entries, and may keep a name that has since been
 * renamed; an entry whose binding moves to another layer follows it, its
 * layer changed and its name and path not. How many variables are misnamed is held at exactly `CEILING`: a
 * rename fails until `CEILING` is lowered by the names it renames. Nothing
 * raises it.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { environmentVariableFor } from "#/config/environment-variable.mjs";
import { RENAMED_VARIABLES_SECTION } from "#/config/removed-keys.mjs";

const PACKAGES = fileURLToPath(new URL("../../../../", import.meta.url));
const TEMPLATE_CONFIG = fileURLToPath(
	new URL("../../../../../templates/standalone/config/", import.meta.url),
);

/**
 * How many variables may still not be named after their paths: exactly as
 * many as are today. A rename lowers it by the names it renames; nothing
 * raises it.
 */
const CEILING = 34;

/** `LEGACY`'s first count: it only ever loses entries. */
const LEGACY_BASELINE = 61;

/**
 * The names that predated the rule, as `<layer>: <VAR> at <path>`, where
 * `<layer>` is a package's directory name, or `template` for the standalone
 * template's layers. Entries are deleted, never added; one follows its
 * binding to another layer (see the file header).
 */
const LEGACY: readonly string[] = [
	"core: CLIENT_TYPE at repositories.client.type",
	"core: CLIENT_PATH at repositories.client.yaml.path",
	"core: CLIENT_USER_TYPE at repositories.user.type",
	"core: CLIENT_USER_PATH at repositories.user.yaml.path",
	"core: CLIENT_USER_AUTHENTICATE_URL at repositories.user.http.authenticateUrl",
	"core: CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL at repositories.user.http.authenticateByTokenUrl",
	"core: CLIENT_USER_LINK_FEDERATED_IDENTITY_URL at repositories.user.http.linkFederatedIdentityUrl",
	"core: CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL at repositories.user.http.findSubjectByFederatedIdentityUrl",
	"core: CLIENT_USER_BEARER_TOKEN at repositories.user.http.bearerToken",
	"core: CLIENT_USER_TIMEOUT at repositories.user.http.timeout",
	"core: CLIENT_USER_MAX_RESPONSE_BYTES at repositories.user.http.maxResponseBytes",
	"core: CLIENT_CODE_TYPE at repositories.code.type",
	"core: CLIENT_CODE_DEFAULT_EXPIRES_IN at repositories.code.memory.defaultExpiresIn",
	"core: CLIENT_CODE_DEFAULT_EXPIRES_IN at repositories.code.redis.defaultExpiresIn",
	"core: CLIENT_CODE_DEFAULT_EXPIRES_IN at redisCodeRepository.defaultExpiresIn",
	"core: CLIENT_CODE_ENDPOINT_URI at repositories.code.redis.endpointUri",
	"core: CLIENT_CODE_PASSWORD at repositories.code.redis.password",
	"core: CLIENT_CODE_KEY_PREFIX at redisCodeRepository.keyPrefix",
	"mfa: MFA_ENCRYPTION_KEY at mfa.encryptionKeys.0.key",
	"template: CLIENT_TYPE at repositories.client.type",
	"template: CLIENT_PATH at repositories.client.yaml.path",
	"template: CLIENT_USER_TYPE at repositories.user.type",
	"template: CLIENT_USER_AUTHENTICATE_URL at repositories.user.http.authenticateUrl",
	"template: CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL at repositories.user.http.authenticateByTokenUrl",
	"template: CLIENT_USER_LINK_FEDERATED_IDENTITY_URL at repositories.user.http.linkFederatedIdentityUrl",
	"template: CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL at repositories.user.http.findSubjectByFederatedIdentityUrl",
	"template: CLIENT_USER_BEARER_TOKEN at repositories.user.http.bearerToken",
	"template: CLIENT_USER_TIMEOUT at repositories.user.http.timeout",
	"template: CLIENT_USER_MAX_RESPONSE_BYTES at repositories.user.http.maxResponseBytes",
	"template: CLIENT_CODE_TYPE at repositories.code.type",
	"template: CLIENT_CODE_DEFAULT_EXPIRES_IN at repositories.code.memory.defaultExpiresIn",
	"template: CLIENT_CODE_DEFAULT_EXPIRES_IN at repositories.code.redis.defaultExpiresIn",
	"template: CLIENT_CODE_ENDPOINT_URI at repositories.code.redis.endpointUri",
	"template: CLIENT_CODE_PASSWORD at repositories.code.redis.password",
];

/**
 * A dotted path in upper snake case, by core's own rule — the one the
 * relocated-path refusal names a key's new variable with, so the guard and the
 * refusal cannot spell a name two ways.
 */
const upperSnake = (path: string): string => environmentVariableFor(path.split("."));

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

/** Whether `path` can be read. */
function readable(path: string): boolean {
	try {
		readFileSync(path);
		return true;
	} catch {
		return false;
	}
}

/**
 * Every configuration layer the repository ships, by the name `LEGACY` gives
 * it: each package's `config/reference.conf` by package directory name, and
 * the standalone template's layers as `template`.
 */
const LAYERS: readonly (readonly [string, string])[] = [
	...readdirSync(PACKAGES, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => [entry.name, join(PACKAGES, entry.name, "config", "reference.conf")] as const),
	...readdirSync(TEMPLATE_CONFIG)
		.filter((file) => file.endsWith(".conf"))
		.map((file) => ["template", join(TEMPLATE_CONFIG, file)] as const),
].filter(([, path]) => readable(path));

/** Every variable each layer substitutes, with each path it sets. */
const FOUND = LAYERS.flatMap(([name, path]) =>
	substitutedNames(readFileSync(path, "utf8")).map((variable) => ({
		package: name,
		variable,
		paths: markedPaths(parseFile(path, { env: { [variable]: MARKER } }).toObject()),
	})),
);

/**
 * Whether `path` is a capture of a renamed variable (`renamed-variables.<NAME>`):
 * no setting, but what the resolution saw of a declared name, held by the
 * package's own `packageReferenceProblems`.
 */
const isCapture = (path: string): boolean => path.startsWith(`${RENAMED_VARIABLES_SECTION}.`);

/** Each variable at a path it is not the upper-snake-case form of, as `LEGACY` writes it. */
const MISNAMED: readonly string[] = FOUND.flatMap(({ package: name, variable, paths }) =>
	paths
		.filter((path) => !isCapture(path) && upperSnake(path) !== variable)
		.map((path) => `${name}: ${variable} at ${path}`),
);

describe("an environment variable is named after the path it sets", () => {
	it("reads the packages' references and the template's layers (the guard is not vacuous)", () => {
		expect(LAYERS.map(([name]) => name)).toEqual(
			expect.arrayContaining(["core", "mfa", "webauthn", "template"]),
		);
		expect(
			LAYERS.filter(([name]) => name === "template").map(([, path]) =>
				path.slice(TEMPLATE_CONFIG.length),
			),
		).toEqual(expect.arrayContaining(["application.conf", "development.conf", "production.conf"]));
		expect(FOUND.filter(({ package: name }) => name === "template").length).toBeGreaterThanOrEqual(
			55,
		);
		expect(FOUND.length).toBeGreaterThan(100);
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
		// A run of capitals is one word, split from the word after it.
		expect(upperSnake("cache.cacheTTLSeconds")).toBe("CACHE_CACHE_TTL_SECONDS");
		expect(upperSnake("oauth.clientIdMetadataDocuments.maxURLBytes")).toBe(
			"OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_URL_BYTES",
		);
	});

	it("names every variable after its path, but for the legacy baseline, and no more of those than the ceiling", () => {
		expect(namingProblems(MISNAMED)).toEqual([]);
	});

	it("keeps the legacy baseline from growing: it only loses entries", () => {
		expect(LEGACY.length).toBeLessThanOrEqual(LEGACY_BASELINE);
	});

	it("holds the ceiling at the number misnamed today: a move pull request lowers it by the names it renames", () => {
		expect(MISNAMED.length).toBe(CEILING);
	});

	describe("probes: what a change that renames names may do", () => {
		const [renamed] = MISNAMED as [string, ...string[]];
		const renaming = MISNAMED.filter((entry) => entry !== renamed);

		it("may rename a legacy name, lowering the ceiling, and leave the list alone", () => {
			expect(namingProblems(renaming, CEILING - 1)).toEqual([]);
		});

		it("may not swap: rename a legacy name and misname a new variable", () => {
			const swapped = [...renaming, "core: NEW_VARIABLE at oauth.newPath"];
			expect(namingProblems(swapped)).not.toEqual([]);
			expect(namingProblems(swapped, CEILING - 1)).not.toEqual([]);
		});
	});
});

/**
 * What the guard finds wrong with `misnamed` — every variable at a path it is
 * not the upper-snake-case form of — under `ceiling`: a misnamed variable the
 * legacy baseline does not hold, and more misnamed variables than the
 * ceiling allows.
 */
function namingProblems(misnamed: readonly string[], ceiling = CEILING): string[] {
	return [
		...misnamed
			.filter((entry) => !LEGACY.includes(entry))
			.map((entry) => `${entry}: not named after its path, and not in the legacy baseline`),
		...(misnamed.length > ceiling
			? [`${misnamed.length} variables are not named after their paths; the ceiling is ${ceiling}`]
			: []),
	];
}
