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
 * The federations the template ships, in core's own section:
 * `core.federations.google` and `core.federations.oidc`, each bound to the
 * variables named after its paths (`CORE_FEDERATIONS_<NAME>_<KEY>`). Phase
 * one chooses the federation modules from the map there. A variable the
 * template bound before, `FEDERATIONS_<NAME>_<KEY>`, set alone or beside its
 * new name at a different value is refused before any module is chosen,
 * naming the new variable and path and never a value; the two at one value
 * are accepted. The map written at the top level refuses boot, naming its
 * paths under `core.federations`.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "@o3co/auth-provider-core";
import { afterAll, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
} from "#/configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** The directories the operator layers are written to, removed after the suite. */
const operatorDirs: string[] = [];
afterAll(() => {
	for (const dir of operatorDirs) rmSync(dir, { recursive: true, force: true });
});

/** The template's own files for the production environment, under an operator's layer when given. */
function ownFiles(hocon?: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	if (hocon === undefined) return [envConfPath, applicationConfPath];
	const dir = mkdtempSync(join(tmpdir(), "core-federations-"));
	operatorDirs.push(dir);
	const file = join(dir, "operator.conf");
	writeFileSync(file, hocon);
	return [file, envConfPath, applicationConfPath];
}

/** Phase one under `env` and an operator's `hocon`. */
const switchesFrom = (env: Record<string, string> = {}, hocon?: string) =>
	readSwitches(readOwnLayers(ownFiles(hocon), { env }));

/** What phase one refuses under `env`. */
function refusal(env: Record<string, string>): Error {
	try {
		switchesFrom(env);
	} catch (err) {
		return err as Error;
	}
	throw new Error("phase one read the switches");
}

/** The federations phase one reads, by name. */
const federationsOf = (env: Record<string, string> = {}) =>
	(switchesFrom(env).core as { federations?: Record<string, Record<string, unknown>> } | undefined)
		?.federations ?? {};

/** The modules phase one chooses under `env`, by name. */
const moduleNames = (env: Record<string, string>) =>
	buildModules(switchesFrom(env), { environment: "production" }).map((module) => module.name);

/** Each variable the template binds: its key under the federation, the old name and the new. */
const RENAMED = [
	["google", "enabled", "FEDERATIONS_GOOGLE_ENABLED", "CORE_FEDERATIONS_GOOGLE_ENABLED", "true"],
	[
		"google",
		"clientId",
		"FEDERATIONS_GOOGLE_CLIENT_ID",
		"CORE_FEDERATIONS_GOOGLE_CLIENT_ID",
		"g-id",
	],
	[
		"google",
		"clientSecret",
		"FEDERATIONS_GOOGLE_CLIENT_SECRET",
		"CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET",
		"g-secret",
	],
	[
		"google",
		"callbackURL",
		"FEDERATIONS_GOOGLE_CALLBACK_URL",
		"CORE_FEDERATIONS_GOOGLE_CALLBACK_URL",
		"https://auth.test/session/oauth/federation/google/callback",
	],
	[
		"google",
		"accessType",
		"FEDERATIONS_GOOGLE_ACCESS_TYPE",
		"CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE",
		"online",
	],
	["oidc", "enabled", "FEDERATIONS_OIDC_ENABLED", "CORE_FEDERATIONS_OIDC_ENABLED", "true"],
	["oidc", "issuer", "FEDERATIONS_OIDC_ISSUER", "CORE_FEDERATIONS_OIDC_ISSUER", "https://idp.test"],
	["oidc", "clientId", "FEDERATIONS_OIDC_CLIENT_ID", "CORE_FEDERATIONS_OIDC_CLIENT_ID", "o-id"],
	[
		"oidc",
		"clientSecret",
		"FEDERATIONS_OIDC_CLIENT_SECRET",
		"CORE_FEDERATIONS_OIDC_CLIENT_SECRET",
		"o-secret",
	],
	[
		"oidc",
		"callbackURL",
		"FEDERATIONS_OIDC_CALLBACK_URL",
		"CORE_FEDERATIONS_OIDC_CALLBACK_URL",
		"https://auth.test/session/oauth/federation/oidc/callback",
	],
] as const;

describe("the federations the template ships, under core.federations", () => {
	it("ships google and oidc disabled, oidc of type oidc", () => {
		const federations = federationsOf();
		expect(federations.google?.enabled).toBe(false);
		expect(federations.oidc).toMatchObject({ enabled: false, type: "oidc" });
	});

	it.each(RENAMED)(
		"reads core.federations.%s.%s from %s's new name",
		(name, key, _old, variable, value) => {
			expect(String(federationsOf({ [variable]: value })[name]?.[key])).toBe(value);
		},
	);

	it("chooses the Google federation's modules when CORE_FEDERATIONS_GOOGLE_ENABLED is true, and none while it is not", () => {
		expect(moduleNames({ CORE_FEDERATIONS_GOOGLE_ENABLED: "true" })).toContain("federation-google");
		expect(moduleNames({})).not.toContain("federation-google");
	});

	it("chooses an OIDC federation's module for an entry of type oidc written under core.federations", () => {
		const names = buildModules(
			switchesFrom(
				{},
				'core.federations.okta { enabled = true, type = "oidc", issuer = "https://okta.test", clientId = "c", clientSecret = "s", callbackURL = "https://auth.test/session/oauth/federation/okta/callback" }\n',
			),
			{ environment: "production" },
		).map((module) => module.name);
		expect(names).toContain("federation-oidc-okta");
	});
});

describe("a variable the template bound before, FEDERATIONS_<NAME>_<KEY>", () => {
	it.each(RENAMED)(
		"core.federations.%s.%s: %s set alone is refused before any module is chosen, naming %s",
		(name, key, old, variable, value) => {
			const err = refusal({ [old]: value });
			expect(err).toBeInstanceOf(RangeError);
			expect(err.message).toContain(`${old} was renamed ${variable}`);
			expect(err.message).toContain(`core.federations.${name}.${key}`);
		},
	);

	it.each(RENAMED)(
		"core.federations.%s.%s: %s beside its new name at a different value is refused, quoting neither",
		(_name, _key, old, variable) => {
			const err = refusal({ [old]: "old-value-5e2d", [variable]: "new-value-c81a" });
			expect(err.message).toContain(old);
			expect(err.message).not.toContain("old-value-5e2d");
			expect(err.message).not.toContain("new-value-c81a");
		},
	);

	it.each(RENAMED)(
		"core.federations.%s.%s: %s beside its new name at the same value is read",
		(name, key, old, variable, value) => {
			expect(String(federationsOf({ [old]: value, [variable]: value })[name]?.[key])).toBe(value);
		},
	);
});

describe("the map written at the top level", () => {
	it("refuses boot, naming its paths under core.federations", async () => {
		const own = readOwnLayers(ownFiles("federations.okta.enabled = false\n"), {
			env: {
				KEY_STORE_LOCAL_SECRET: "core-federations-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_STORE_SECRET: "core-federations-session.at-least-32-bytes.ok",
			},
		});
		const switches = readSwitches(own);
		const modules = buildModules(switches, { environment: "production" });
		await expect(
			createApp({
				modules,
				bootstrapComponents: {
					config: resolveForBoot(own, modules, expectedSessionRequirements(switches)),
					pathResolver: (s: string) => s,
				} as never,
			}),
		).rejects.toMatchObject({
			reason: "config-path-relocated",
			details: {
				relocated: [
					expect.objectContaining({
						from: "federations.okta.enabled",
						to: "core.federations.okta.enabled",
						environmentVariable: "CORE_FEDERATIONS_OKTA_ENABLED",
					}),
				],
			},
		});
	});
});
