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

import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { overlayConfig } from "#/config/composed.mjs";
import { CORE_RELOCATIONS } from "#/config/core-relocations.mjs";
import { coreReference } from "#/config/references.mjs";
import { RENAMED_VARIABLES_SECTION } from "#/config/removed-keys.mjs";
import * as coreExports from "#/index.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { referenceConfProblems } from "#/testing/referenceConf.mjs";
import { renamedVariableProblems } from "#/testing/renamedVariables.mjs";

/** What core's base makes of `raw`, laid over it: boot's first parse. */
const parsedByBase = (raw: unknown): unknown => overlayConfig(raw, CoreConfigSchema.parse(raw));

/**
 * Core's `reference.conf` holds only what core's schema declares, and the
 * sections of core's own modules that declare it as their reference.
 *
 * Boot's composed parse lays each schema's output over what was written, so
 * nothing strips at boot (`boot/__tests__/composed-parse.test.mts`; across
 * every package, the full-set composition in `tools/composition`), and each
 * package checks its own `reference.conf` against its modules' sections
 * (`packageReferenceProblems`). What stays here is core's own file against
 * core's own schema: resolved and parsed with core's base
 * (`CoreConfigSchema`), with nothing laid back over it, any path the file has
 * and the parse lacks is a
 * default core ships that core's schema does not declare — one no reader is
 * sure to see — unless it lies in the section of one of core's own modules
 * that declares this file, whose schema holds it instead. The captures of
 * the variables core's own section declares
 * renamed (`renamed-variables`) are no setting: boot removes them before its
 * parse, and the file captures exactly the names `CORE_RELOCATIONS` declares.
 */

const REFERENCE_CONF_PATH = fileURLToPath(
	new URL("../../../config/reference.conf", import.meta.url),
);

const REPO_ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));

/** The three substitutions `reference.conf` cannot validate without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "reference-conf-drift.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "reference-conf-drift-session.at-least-32-bytes.ok",
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Every dotted path in `tree`, branches and leaves alike. Arrays are leaves:
 * their elements are values, not configuration keys.
 */
function collectPaths(tree: unknown, prefix = ""): string[] {
	if (!isPlainObject(tree)) return [];
	return Object.entries(tree).flatMap(([key, value]) => {
		const path = prefix === "" ? key : `${prefix}.${key}`;
		return [path, ...collectPaths(value, path)];
	});
}

/** Whether `path` is the captures of renamed variables, or one of them. */
const isCapture = (path: string): boolean =>
	path === RENAMED_VARIABLES_SECTION || path.startsWith(`${RENAMED_VARIABLES_SECTION}.`);

/** Core's exported modules that declare core's own `reference.conf` as their section's reference. */
const CORE_MODULES: readonly Module[] = Object.values(coreExports).filter(
	(value): value is Module =>
		typeof value === "object" &&
		value !== null &&
		(value as Module).section?.reference?.href === coreReference().href,
);

/** The top-level sections `CORE_MODULES` read. */
const CORE_MODULE_SECTIONS: readonly string[] = CORE_MODULES.map((module) => module.name);

/** Whether `path` lies in the section of one of core's own modules. */
const inCoreModuleSection = (path: string): boolean =>
	CORE_MODULE_SECTIONS.some((section) => path === section || path.startsWith(`${section}.`));

function hasPath(tree: unknown, path: string): boolean {
	let cursor: unknown = tree;
	for (const segment of path.split(".")) {
		if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment)) return false;
		cursor = cursor[segment];
	}
	return true;
}

describe("core's reference.conf holds only what core's schema declares", () => {
	const resolved = parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV }).toObject();
	// The base alone, stripping what it does not declare: nothing laid back over it.
	const parsed = CoreConfigSchema.parse(resolved);

	it("resolves to a non-trivial tree, so the diff below is over something", () => {
		const paths = collectPaths(resolved);
		expect(paths.length).toBeGreaterThan(30);
		expect(paths).toContain("core.tokenBinding.dispatchPolicy");
		expect(paths).toContain("core-rate-limiter-memory.maxBuckets");
	});

	it("ships no path core's schema does not declare, outside its own modules' sections", () => {
		const stripped = collectPaths(resolved).filter(
			(path) => !isCapture(path) && !inCoreModuleSection(path) && !hasPath(parsed, path),
		);
		// A path listed here is a section core's `reference.conf` ships that
		// core's schema does not declare. Declare it where it belongs, or move
		// the default to the package that owns the section, rather than adding
		// it to an allowlist here.
		expect(stripped).toEqual([]);
	});
});

describe("core's reference.conf holds the sections of core's own modules to their schemas", () => {
	it("finds them: the JWKS module's and the in-process stores' among them (the guard is not vacuous)", () => {
		expect(CORE_MODULE_SECTIONS).toEqual(
			expect.arrayContaining([
				"jwks",
				"core-challenge-store-memory",
				"core-federation-grant-store-memory",
				"core-mfa-transaction-store-memory",
				"core-rate-limiter-memory",
				"core-replay-seen-set-memory",
			]),
		);
	});

	it.each([
		["with no variable set", {}],
		[
			"with each variable set",
			{
				JWKS_PATH: "/keys/jwks.json",
				JWKS_CACHE_MAX_AGE: "60",
				CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "500",
			},
		],
	])("parses each without losing a path, %s", (_label, env) => {
		const tree = parseFile(REFERENCE_CONF_PATH, {
			env: { ...REQUIRED_ENV, ...env },
		}).toObject() as Record<string, unknown>;
		expect(
			referenceConfProblems({
				tree: Object.fromEntries(CORE_MODULE_SECTIONS.map((section) => [section, tree[section]])),
				reference: coreReference(),
				modules: CORE_MODULES,
			}),
		).toEqual([]);
	});
});

describe("core's reference.conf captures exactly the variables core's own section and core's own modules declare renamed", () => {
	it("captures each of their names, binds each new one at its path, and captures nothing else", () => {
		const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
			parseFile(path, { env: { ...REQUIRED_ENV, ...env } }).toObject();
		expect(
			renamedVariableProblems({
				modules: CORE_MODULES,
				core: CORE_RELOCATIONS,
				layers: [REFERENCE_CONF_PATH],
				read,
			}),
		).toEqual([]);
	});
});

describe("core's reference.conf binds core's own section and its modules', and nothing at the paths they moved from", () => {
	const MARKER = "__CORE_SECTION_MARKER__";
	/** Every dotted path the file sets to `MARKER` with `variable` set to it. */
	const pathsSetBy = (variable: string): string[] => {
		const paths: string[] = [];
		const walk = (tree: unknown, prefix: string): void => {
			if (tree === MARKER) paths.push(prefix);
			if (typeof tree !== "object" || tree === null) return;
			for (const [key, value] of Object.entries(tree)) {
				walk(value, prefix === "" ? key : `${prefix}.${key}`);
			}
		};
		walk(
			parseFile(REFERENCE_CONF_PATH, { env: { ...REQUIRED_ENV, [variable]: MARKER } }).toObject(),
			"",
		);
		return paths.filter((path) => !isCapture(path)).sort();
	};

	it.each([
		["CORE_DEPLOYMENT_MODE", "core.deployment.mode"],
		["JWKS_PATH", "jwks.path"],
		["JWKS_CACHE_MAX_AGE", "jwks.cacheMaxAge"],
		["CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS", "core-rate-limiter-memory.maxBuckets"],
	])("binds %s at %s alone", (variable, path) => {
		expect(pathsSetBy(variable)).toEqual([path]);
	});

	it.each(["DEPLOYMENT_MODE", "MEMORY_RATE_LIMITER_MAX_BUCKETS", "RATE_LIMIT_FAIL_MODE"])(
		"binds %s nowhere but its capture",
		(variable) => {
			expect(pathsSetBy(variable)).toEqual([]);
		},
	);

	it("captures DEPLOYMENT_MODE and CORE_DEPLOYMENT_MODE as the resolution sees them", () => {
		const captured = (env: Record<string, string>) =>
			(
				parseFile(REFERENCE_CONF_PATH, { env: { ...REQUIRED_ENV, ...env } }).toObject() as Record<
					string,
					unknown
				>
			)[RENAMED_VARIABLES_SECTION];
		expect(captured({})).toMatchObject({ DEPLOYMENT_MODE: null, CORE_DEPLOYMENT_MODE: null });
		expect(captured({ DEPLOYMENT_MODE: "multi" })).toMatchObject({
			DEPLOYMENT_MODE: "multi",
			CORE_DEPLOYMENT_MODE: null,
		});
	});

	it("sets nothing at oauth {}, the oauth module's, nor at the paths core's section, the JWKS module's and the stores' moved from", () => {
		const tree = parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV }).toObject();
		for (const path of [
			"deployment",
			"sessionRequirements",
			"oauth",
			"oauth.jwt.jwksPath",
			"oauth.jwt.jwksCacheMaxAge",
			"memoryRateLimiter",
			"redisRateLimiter",
			"rateLimit.failMode",
			"redisAccessTokenDenylist",
			"redisConsentStore",
			"redisMfaFactorStore",
			"redisMfaTransactionStore",
			"redisRefreshTokenFamilyStore",
			"redisSessionStores",
			"redisFederationTokenStore",
			"federationGrants",
			"redisFederationGrantStore",
		]) {
			expect(hasPath(tree, path), path).toBe(false);
		}
	});
});

describe("the WebAuthn origin lists reach the composition root as the string the environment set", () => {
	// An environment variable carries a list only as one string, so
	// `WEBAUTHN_ORIGIN=https://a.example,https://b.example` has to survive
	// HOCON resolution and core's parse intact for
	// `webauthnConfigSchema` — which decides the list's shape, as it does for
	// `CORS_ALLOWED_ORIGINS` here — to split it. The webauthn package's
	// `module.boot.test.mts` boots from exactly this section; this is the half
	// that needs the HOCON library, which that package does not depend on.
	const WEBAUTHN_CONF_PATH = join(REPO_ROOT, "packages/webauthn/config/reference.conf");

	it("keeps WEBAUTHN_ORIGIN and WEBAUTHN_TOP_ORIGIN as one comma-separated string each", () => {
		const env = {
			...REQUIRED_ENV,
			WEBAUTHN_RP_ID: "example.com",
			WEBAUTHN_RP_NAME: "Example App",
			WEBAUTHN_ORIGIN: "https://a.example,https://b.example",
			WEBAUTHN_TOP_ORIGIN: "https://partner.example",
		};
		const chained = parseFile(WEBAUTHN_CONF_PATH, { env }).withFallback(
			parseFile(REFERENCE_CONF_PATH, { env }),
		);
		const parsed = parsedByBase(chained.toObject()) as {
			webauthn?: Record<string, unknown>;
		};
		expect(parsed.webauthn?.origin).toBe("https://a.example,https://b.example");
		expect(parsed.webauthn?.topOrigin).toBe("https://partner.example");
	});
});
