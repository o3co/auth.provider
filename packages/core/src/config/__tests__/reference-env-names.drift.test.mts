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
 * It reads every package's `config/reference.conf` and the standalone
 * template's configuration layers (`templates/standalone/config/*.conf`):
 * each `${?VAR}` (or `${VAR}`) outside a comment is resolved alone, set to a
 * marker, and the paths the marker lands on are the paths the variable sets.
 * A name that is not the upper-snake-case form of each of its paths fails,
 * unless it is on `TODAY`: the names that predate the rule, which the move
 * pull requests rename. That list may only shrink, and two checks hold it
 * there: an entry that no longer holds fails until it is removed, and the
 * list's length has a ceiling, `TODAY_CEILING`, that a name added to it
 * breaks — each move pull request lowers the ceiling by the names it renames.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";

const PACKAGES = fileURLToPath(new URL("../../../../", import.meta.url));
const TEMPLATE_CONFIG = fileURLToPath(
	new URL("../../../../../templates/standalone/config/", import.meta.url),
);

/**
 * How long `TODAY` may be: its length today. A move pull request that renames
 * names lowers it by as many; nothing raises it.
 */
const TODAY_CEILING = 61;

/**
 * The names that predate the rule, as `<layer>: <VAR> at <path>` — `<layer>`
 * is a package's directory name, or `template` for the standalone template's
 * layers; the move pull requests rename them.
 */
const TODAY: readonly string[] = [
	"core: LOG_LEVEL at logging.level",
	"core: OAUTH_JWT_ALGORITHM at oauth.jwt.signingKey.local.algorithm",
	"core: OAUTH_JWT_KID at oauth.jwt.signingKey.local.kid",
	"core: OAUTH_JWT_SECRET at oauth.jwt.signingKey.local.secret",
	"core: OAUTH_JWT_PRIVATE_KEY_PATH at oauth.jwt.signingKey.local.privateKeyPath",
	"core: OAUTH_JWT_PUBLIC_KEY_PATH at oauth.jwt.signingKey.local.publicKeyPath",
	"core: OAUTH_JWT_PRIVATE_KEY at oauth.jwt.signingKey.local.privateKey",
	"core: OAUTH_JWT_PUBLIC_KEY at oauth.jwt.signingKey.local.publicKey",
	"core: OAUTH_GRANTS_JWT_BEARER_ENABLED at oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer.enabled",
	"core: OAUTH_CIMD_ENABLED at oauth.clientIdMetadataDocuments.enabled",
	"core: OAUTH_CIMD_ALLOWED_SCOPES at oauth.clientIdMetadataDocuments.allowedScopes",
	"core: OAUTH_CIMD_ALLOWED_AUDIENCES at oauth.clientIdMetadataDocuments.allowedAudiences",
	"core: OAUTH_CIMD_ALLOWED_HOSTS at oauth.clientIdMetadataDocuments.allowedHosts",
	"core: OAUTH_CIMD_DENIED_HOSTS at oauth.clientIdMetadataDocuments.deniedHosts",
	"core: OAUTH_CIMD_MAX_BYTES at oauth.clientIdMetadataDocuments.maxBytes",
	"core: OAUTH_CIMD_TIMEOUT_MS at oauth.clientIdMetadataDocuments.timeoutMs",
	"core: OAUTH_CIMD_CACHE_MAX_AGE_MS at oauth.clientIdMetadataDocuments.cacheMaxAgeMs",
	"core: OAUTH_CIMD_MAX_CACHE_ENTRIES at oauth.clientIdMetadataDocuments.maxCacheEntries",
	"core: OAUTH_CIMD_STALE_IF_ERROR_MS at oauth.clientIdMetadataDocuments.staleIfErrorMs",
	"core: OAUTH_CIMD_NEGATIVE_CACHE_MS at oauth.clientIdMetadataDocuments.negativeCacheMs",
	"core: OAUTH_CIMD_MAX_CONCURRENT_FETCHES at oauth.clientIdMetadataDocuments.maxConcurrentFetches",
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
	"core: REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX at redisRefreshTokenFamilyStore.keyPrefix",
	"core: REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT at redisRefreshTokenFamilyStore.casRetryLimit",
	"core: CLIENT_CODE_KEY_PREFIX at redisCodeRepository.keyPrefix",
	"mfa: MFA_ENCRYPTION_KEY at mfa.encryptionKeys.0.key",
	"mfa: MFA_TOTP_ENABLED at mfa.factors.totp.enabled",
	"mfa: MFA_TOTP_ISSUER at mfa.factors.totp.issuer",
	"webauthn: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT at webauthn.rateLimit.authenticationOptions.limit",
	"webauthn: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS at webauthn.rateLimit.authenticationOptions.windowSeconds",
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
 * A path in upper snake case: each key split at its capitals and hyphens — a
 * run of capitals is one word, split from a capitalised word after it — and
 * the keys joined by `_`.
 */
const upperSnake = (path: string): string =>
	path
		.split(".")
		.map((key) =>
			key
				.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
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
 * Every configuration layer the repository ships, by the name `TODAY` gives
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

/** Each variable at a path it is not the upper-snake-case form of, as `TODAY` writes it. */
const MISNAMED: readonly string[] = FOUND.flatMap(({ package: name, variable, paths }) =>
	paths
		.filter((path) => upperSnake(path) !== variable)
		.map((path) => `${name}: ${variable} at ${path}`),
);

describe("an environment variable is named after the path it sets (#728 B9)", () => {
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

	it("names every variable after its path, but for the names that predate the rule", () => {
		expect(MISNAMED.filter((entry) => !TODAY.includes(entry))).toEqual([]);
	});

	it("keeps no name on the list that is now named after its path: the list only shrinks", () => {
		expect(TODAY.filter((entry) => !MISNAMED.includes(entry))).toEqual([]);
	});

	it("adds no name to the list: its length stays under the ceiling the move pull requests lower", () => {
		expect(TODAY.length).toBeLessThanOrEqual(TODAY_CEILING);
	});
});
