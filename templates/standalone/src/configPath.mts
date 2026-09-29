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
 * Where the template's configuration comes from, and the two phases it is
 * read in (#728).
 *
 * The composition's own layers — `{env}.conf` over `application.conf` — are
 * read once (`readOwnLayers`): each file parsed once, under one snapshot of
 * the environment. Both phases are built from that one read:
 *
 * 1. `readSwitches` — the snapshot over core's `reference.conf` — parses the
 *    switches the template chooses its modules by (`SWITCHES`), before it
 *    knows them;
 * 2. `resolveForBoot` — the same snapshot over the `reference.conf` of every
 *    package the loaded modules come from, core's last — is what `createApp`
 *    parses, once.
 *
 * So a switch phase one reads is the value boot's parse has — a file
 * replaced, or a variable changed, while the process starts cannot split
 * them (adapter selections have no disagreement guard at boot) — pinned for
 * the shipped environments by `two-phase-config.test.mts`. Two limits, both
 * of what phase one layers rather than of when it reads: a switch only a
 * package's `reference.conf` sets reads as unset in phase one, and a loaded
 * module's own schema may make something else of a switch at boot.
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
import { type Config, empty, parseFile } from "@o3co/ts.hocon";

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
	 * The environment `${?VAR}` substitutions read — a snapshot of the
	 * process's when unset. Tests pass their own.
	 */
	readonly env?: Readonly<Record<string, string>>;
}

/**
 * The composition's own layers, read once (#728): its files parsed once, and
 * the snapshot of the environment every layer's `${?VAR}` substitutes. Both
 * phases are built from one read, so a file replaced while the process
 * starts, or a variable changed, cannot make boot parse something other than
 * what the switches were read from.
 */
export interface OwnLayers {
	/** The composition's own files, highest first, parsed and layered. */
	readonly config: Config;
	/** The environment the files were substituted with; the references are too. */
	readonly env: Readonly<Record<string, string>>;
}

/**
 * Read the composition's own files — highest first, `{env}.conf` then
 * `application.conf` — once, under one snapshot of the environment
 * (`options.env`, or the process's as it is now).
 */
export function readOwnLayers(
	ownFiles: readonly string[],
	options: ResolveOptions = {},
): OwnLayers {
	const env: Readonly<Record<string, string>> = {
		...(options.env ??
			Object.fromEntries(
				Object.entries(process.env).filter(
					(entry): entry is [string, string] => entry[1] !== undefined,
				),
			)),
	};
	const config = ownFiles.reduce<Config>(
		(layered, file) => layered.withFallback(parseFile(file, { env: { ...env } })),
		empty(),
	);
	return { config, env };
}

/**
 * The composition's configuration, resolved to plain data and parsed by
 * nothing (#728): its own layers, read once (`readOwnLayers`), over
 * `references`, the `reference.conf` files of the packages it loads, in the
 * order `moduleReferences` answers them (core's last), substituted with the
 * same environment. A path set in two layers takes the higher one's value.
 */
export function resolveLayers(own: OwnLayers, references: readonly URL[]): Record<string, unknown> {
	const layered = references.reduce<Config>(
		(config, reference) =>
			config.withFallback(parseFile(fileURLToPath(reference), { env: { ...own.env } })),
		own.config,
	);
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

export interface SwitchesOptions {
	/** Paths read beside `SWITCHES`: what a module a deployment adds reads when it is built. */
	readonly reads?: readonly string[];
}

/**
 * Phase one, transitional (#728): the switches (`SWITCHES`, and `reads`) from
 * the composition's own layers over core's `reference.conf` alone, read with
 * core's `readTransitionalConfig` — each parsed with the schema core declares
 * at its path, everything else as written. Use it for those choices only.
 *
 * Phase one sees nothing a package's `reference.conf` alone sets: before the
 * modules are known, no package's reference is layered. A switch whose
 * default only a package ships reads as unset here; set it in the template's
 * own files. It goes when the switches move into the template's own section,
 * the only one read before the modules are chosen (#728 B5).
 */
export function readSwitches(own: OwnLayers, options: SwitchesOptions = {}): AppConfig {
	return readTransitionalConfig(resolveLayers(own, [coreReference()]), [
		...SWITCHES,
		...(options.reads ?? []),
	]);
}

/**
 * Phase two: the configuration `createApp` parses — once, with every loaded
 * module's schema (#728) — from the composition's own layers, the same read
 * phase one had, over the `reference.conf` of every package `modules` come
 * from, core's last, as resolved and unparsed. `sessionRequirements` is the posture on session
 * admission, derived from the parsed `mfa.mode` in phase one (the
 * session-admission ADR's D7) and written in beside what was resolved.
 *
 * Typed as `AppConfig` because that is the `config` slot's type, which is
 * what `createApp`'s parse makes of it; read the parsed configuration from
 * the handle (`handle.components.config`), not from this.
 */
export function resolveForBoot(
	own: OwnLayers,
	modules: readonly Module[],
	sessionRequirements: AppConfig["sessionRequirements"],
): AppConfig {
	const resolved = resolveLayers(own, moduleReferences(modules));
	return { ...resolved, sessionRequirements } as unknown as AppConfig;
}
