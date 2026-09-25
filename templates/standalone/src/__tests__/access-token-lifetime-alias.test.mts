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
 * `oauth.accessToken.expiresIn` / OAUTH_ACCESS_TOKEN_EXPIRES_IN is a deprecated
 * alias of `defaultExpiresIn`, and the composition says so once — the OR-9
 * shape `repositories.code.type` already has.
 *
 * The line has to be exact in both directions. Core's `reference.conf` keeps
 * the shipped lifetime on the deprecated key, so "the alias supplied the
 * default" describes every deployment that set nothing; warning on that would
 * train operators to ignore the line. Only an override of the old key is
 * something to move.
 */

import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema, type Logger } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "access-token-alias.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "access-token-alias-session.at-least-32-bytes.ok",
};

/** The shipped layers, resolved the way `app.mts` resolves them. */
function loadShipped(env: Record<string, string> = {}): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "development");
	const resolvedEnv = { ...REQUIRED_ENV, ...env };
	return validate(
		parseFile(envConfPath, { env: resolvedEnv })
			.withFallback(parseFile(applicationConfPath, { env: resolvedEnv }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env: resolvedEnv })),
		AppConfigSchema,
	);
}

/** What `buildModules` hands the logger it is given, per level. */
function logged(config: AppConfig): Array<{ level: string; args: unknown[] }> {
	const calls: Array<{ level: string; args: unknown[] }> = [];
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
		};
	const logger: Logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	buildModules(config, { logger });
	return calls;
}

/** The one line the alias is reported by: object-first, an event name, at warn. */
const ALIAS_WARNING = {
	level: "warn",
	args: [
		{
			key: "oauth.accessToken.expiresIn",
			env: "OAUTH_ACCESS_TOKEN_EXPIRES_IN",
			replacement: "oauth.accessToken.defaultExpiresIn",
			replacementEnv: "OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN",
		},
		"config_key_deprecated",
	],
};

/** Every line `buildModules` writes about the deprecated key. */
const aliasWarnings = (config: AppConfig) =>
	logged(config).filter(
		({ args }) => (args[0] as { key?: unknown } | undefined)?.key === "oauth.accessToken.expiresIn",
	);

describe("the deprecated access-token lifetime alias", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("says nothing for a deployment that sets no lifetime at all", () => {
		// Also what keeps the template's idea of "the shipped value" honest: it
		// is measured against core's real `reference.conf`, so a change to the
		// shipped literal fails here rather than warning every deployment.
		expect(aliasWarnings(loadShipped())).toEqual([]);
	});

	it("says nothing for a deployment on the new variable", () => {
		expect(aliasWarnings(loadShipped({ OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "900" }))).toEqual(
			[],
		);
	});

	it("warns once, object-first, when OAUTH_ACCESS_TOKEN_EXPIRES_IN still decides the default", () => {
		expect(logged(loadShipped({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900" }))).toEqual([ALIAS_WARNING]);
	});

	it("warns for a hand-built configuration that overrides only the old key", () => {
		const config = loadShipped();
		expect(
			aliasWarnings({
				...config,
				oauth: { ...config.oauth, accessToken: { expiresIn: 900 } },
			}),
		).toEqual([ALIAS_WARNING]);
	});

	it("writes the same line through consoleLogger when no logger is handed over", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		buildModules(loadShipped({ OAUTH_ACCESS_TOKEN_EXPIRES_IN: "900" }));
		expect(warn.mock.calls).toEqual([ALIAS_WARNING.args]);
	});
});
