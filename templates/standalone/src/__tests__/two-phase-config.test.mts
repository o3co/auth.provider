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
 * The template reads its configuration in two phases (#728), as `app.mts`
 * does:
 *
 * 1. `readSwitches` — its own files over core's `reference.conf`, read with
 *    core's transitional reader — for what it needs before it knows its
 *    modules: the switches `buildModules` chooses them by, the log level,
 *    `mfa.mode`;
 * 2. `resolveForBoot` — its own files over the `reference.conf` of every
 *    package its modules come from, core's last — handed to `createApp`
 *    unparsed, which parses it once with every loaded module's schema.
 *
 * Where the template used to parse with `AppConfigSchema` (through the HOCON
 * library's Zod bridge) before `buildModules`, phase one must read every value
 * that parse did: the template's values are unchanged.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AppConfigSchema, type Module } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { buildModules, withSessionRequirements } from "../buildModules.mjs";
import {
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
	resolveLibraryReferenceConfPath,
} from "../configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "two-phase-config-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "two-phase-config-session.at-least-32-bytes.ok",
};

/** The environments the template ships for: none but the secrets, and the Redis-backed production one. */
const ENVIRONMENTS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
	"the secrets alone": REQUIRED_ENV,
	"every adapter on Redis, MFA optional": {
		...REQUIRED_ENV,
		DEPLOYMENT_MODE: "multi",
		SESSION_STORAGE_TYPE: "redis",
		SESSION_STORAGE_REDIS_URL: "redis://redis:6379",
		REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis:6379",
		USER_SESSION_STORES_ADAPTER: "redis",
		RATE_LIMITER_ADAPTER: "redis",
		OAUTH_CODE_ADAPTER: "redis",
		HTTP_PORT: "8080",
		HTTP_TRUST_PROXY: "loopback",
		SESSION_SECURE: "false",
		MFA_MODE: "optional",
	},
};

const ownFiles = (environment: string): string[] => {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, environment);
	return [envConfPath, applicationConfPath];
};

/** What `app.mts` read before #728: the layers parsed with `AppConfigSchema` through the bridge. */
function preParsed(environment: string, env: Readonly<Record<string, string>>): unknown {
	const read = (file: string) => parseFile(file, { env: { ...env } });
	const [top, application] = ownFiles(environment) as [string, string];
	return validate(
		read(top).withFallback(read(application)).withFallback(read(resolveLibraryReferenceConfPath())),
		AppConfigSchema,
	);
}

/** Every leaf of `before` whose value `after` does not hold at the same path. */
function changedLeaves(before: unknown, after: unknown, path: readonly string[] = []): string[] {
	const isObject = (value: unknown): value is Record<string, unknown> =>
		typeof value === "object" && value !== null && !Array.isArray(value);
	if (isObject(before) && Object.keys(before).length > 0) {
		return Object.keys(before).flatMap((key) =>
			changedLeaves(before[key], isObject(after) ? after[key] : undefined, [...path, key]),
		);
	}
	return JSON.stringify(before) === JSON.stringify(after) ? [] : [path.join(".")];
}

describe("phase one reads every value the template's AppConfigSchema pre-parse read", () => {
	for (const environment of ["development", "production"]) {
		for (const [name, env] of Object.entries(ENVIRONMENTS)) {
			it(`${environment}, ${name}`, () => {
				const before = preParsed(environment, env);
				const switches = readSwitches(ownFiles(environment), { env });
				expect(changedLeaves(before, switches)).toEqual([]);
			});
		}
	}
});

describe("phase two: what createApp is handed", () => {
	const env = ENVIRONMENTS["the secrets alone"] as Readonly<Record<string, string>>;
	const switches = withSessionRequirements(readSwitches(ownFiles("development"), { env }));

	/**
	 * A package the template does not load, shipping a reference.conf of its
	 * own: only its manifest's `section.reference` is read here, so the
	 * manifest carries nothing else.
	 */
	function widgetModule(): Module {
		const dir = mkdtempSync(join(tmpdir(), "two-phase-config-"));
		const reference = join(dir, "reference.conf");
		writeFileSync(
			reference,
			'widget { size = 3 }\nhttp { port = 1 }\nlogging { level = "widget-level" }\n',
		);
		return {
			name: "widget",
			section: { reference: pathToFileURL(reference) },
		} as unknown as Module;
	}

	it("layers each loaded module's reference beneath the template's own files, over core's", () => {
		const modules = [...buildModules(switches, { environment: "development" }), widgetModule()];
		const resolved = resolveForBoot(
			ownFiles("development"),
			modules,
			switches.sessionRequirements,
			{
				env,
			},
		) as unknown as Record<string, Record<string, unknown>>;
		// The package's own section, from its reference.
		expect(resolved.widget).toEqual({ size: 3 });
		// The template's application.conf wins over a package's reference…
		expect(resolved.http?.port).toBe(3000);
		// …and a package's reference over core's.
		expect(resolved.logging?.level).toBe("widget-level");
	});

	it("layers no reference a loaded module does not declare", () => {
		const modules = buildModules(switches, { environment: "development" });
		const resolved = resolveForBoot(
			ownFiles("development"),
			modules,
			switches.sessionRequirements,
			{
				env,
			},
		) as unknown as Record<string, unknown>;
		expect(resolved).not.toHaveProperty("widget");
	});

	it("hands the configuration over as resolved, unparsed, with phase one's posture on session admission", () => {
		const optional = withSessionRequirements(
			readSwitches(ownFiles("development"), {
				env: { ...env, MFA_MODE: "optional", HTTP_PORT: "8080" },
			}),
		);
		const resolved = resolveForBoot(
			ownFiles("development"),
			buildModules(switches, { environment: "development" }),
			optional.sessionRequirements,
			{ env: { ...env, MFA_MODE: "optional", HTTP_PORT: "8080" } },
		) as unknown as Record<string, Record<string, unknown>>;
		// An environment variable's string, as HOCON substituted it: createApp parses it.
		expect(resolved.http?.port).toBe("8080");
		expect(resolved.sessionRequirements).toEqual({ expected: ["mfa"] });
	});
});
