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

import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	coreReference,
	type Module,
	moduleReferences,
	readTransitionalConfig,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";

export interface ResolvedConfigPaths {
	readonly applicationConfPath: string;
	readonly envConfPath: string;
}

export function resolveConfigPaths(configDirPath: string, env: string): ResolvedConfigPaths {
	// path.resolve strips trailing slashes that fileURLToPath may preserve, so
	// the containment check below compares equal shapes (path.dirname never
	// returns a trailing separator).
	const normalizedConfigDir = path.resolve(configDirPath);
	const applicationConfPath = path.join(normalizedConfigDir, "application.conf");
	const envConfPath = path.resolve(normalizedConfigDir, `${env}.conf`);
	if (path.dirname(envConfPath) !== normalizedConfigDir) {
		throw new Error(
			`Invalid config environment name: "${env}" resolves outside ${normalizedConfigDir}`,
		);
	}
	return { applicationConfPath, envConfPath };
}

export interface ResolveOptions {
	/**
	 * The environment `${?VAR}` substitutions read — the process's when
	 * unset. Tests pass their own.
	 */
	readonly env?: Readonly<Record<string, string>>;
}

/**
 * The composition's configuration, resolved to plain data and parsed by
 * nothing (#728): its own files, highest first — `{env}.conf`, then
 * `application.conf` — over `references`, the `reference.conf` files of the
 * packages it loads, in the order `moduleReferences` answers them (core's
 * last). A path set in two layers takes the higher one's value.
 */
export function resolveLayers(
	ownFiles: readonly string[],
	references: readonly URL[],
	options: ResolveOptions = {},
): Record<string, unknown> {
	const read = (file: string) =>
		options.env === undefined ? parseFile(file) : parseFile(file, { env: { ...options.env } });
	const [top, ...below] = [...ownFiles, ...references.map((reference) => fileURLToPath(reference))];
	if (top === undefined) return {};
	const layered = below.reduce((config, file) => config.withFallback(read(file)), read(top));
	return layered.toObject() as Record<string, unknown>;
}

/**
 * What the template reads before it knows its modules (#728, transitional):
 * the switches `buildModules` and the module factories it calls choose by,
 * the log level (`logger.mts`) and `mfa.mode` (the posture on session
 * admission). Phase one parses these paths and nothing else — boot validates
 * the whole configuration — so a module a deployment adds to `buildModules`
 * that reads its configuration when it is built adds the paths it reads here
 * (or passes them to `readSwitches` as `reads`). Held to what the template
 * reads by `two-phase-config.test.mts`.
 *
 * Every path here, and in `reads`, must be one core's transitional base
 * declares — a section core's schema has, or mirrors for a package — or
 * `readSwitches` refuses it. A deployment module that reads a key of its own,
 * one core does not mirror, when it is built reads it as written: raw, an
 * environment variable's string and all, and with nothing a package's
 * `reference.conf` alone sets. Parse it in the module, or read it after boot.
 */
export const SWITCHES: readonly string[] = [
	"logging",
	"mfa.mode",
	"federations",
	"federationGrants.enabled",
	"federationGrantStore.adapter",
	"federationGrantIntentStore.adapter",
	"federationTokenStore.type",
	"rateLimiter.adapter",
	"userSessionStores.adapter",
	"accessTokenDenylist.adapter",
	"replaySeenSet.adapter",
	"consentStore.adapter",
	"session.storage",
	"repositories.code",
	"oauth.code.adapter",
	"oauth.grants",
	"oauth.accessToken",
];

export interface SwitchesOptions extends ResolveOptions {
	/** Paths read beside `SWITCHES`: what a module a deployment adds reads when it is built. */
	readonly reads?: readonly string[];
}

/**
 * Phase one, transitional (#728): the switches (`SWITCHES`, and `reads`) from
 * the template's own files over core's `reference.conf` alone, read with core's
 * `readTransitionalConfig` — each parsed with the schema core declares at its
 * path, everything else as written. Use it for those choices only.
 *
 * Phase one sees nothing a package's `reference.conf` alone sets: before the
 * modules are known, no package's reference is layered. A switch whose
 * default only a package ships reads as unset here; set it in the template's
 * own files. It goes when the switches move into the template's own section,
 * the only one read before the modules are chosen (#728 B5).
 */
export function readSwitches(
	ownFiles: readonly string[],
	options: SwitchesOptions = {},
): AppConfig {
	return readTransitionalConfig(resolveLayers(ownFiles, [coreReference()], options), [
		...SWITCHES,
		...(options.reads ?? []),
	]);
}

/**
 * Phase two: the configuration `createApp` parses — once, with every loaded
 * module's schema (#728) — from the composition's own files over the
 * `reference.conf` of every package `modules` come from, core's last, as
 * resolved and unparsed. `sessionRequirements` is the posture on session
 * admission, derived from the parsed `mfa.mode` in phase one (the
 * session-admission ADR's D7) and written in beside what was resolved.
 *
 * Typed as `AppConfig` because that is the `config` slot's type, which is
 * what `createApp`'s parse makes of it; read the parsed configuration from
 * the handle (`handle.components.config`), not from this.
 */
export function resolveForBoot(
	ownFiles: readonly string[],
	modules: readonly Module[],
	sessionRequirements: AppConfig["sessionRequirements"],
	options: ResolveOptions = {},
): AppConfig {
	const resolved = resolveLayers(ownFiles, moduleReferences(modules), options);
	return { ...resolved, sessionRequirements } as unknown as AppConfig;
}
