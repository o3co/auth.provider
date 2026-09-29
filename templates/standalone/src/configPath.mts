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

import { createRequire } from "node:module";
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

const REFERENCE_CONF_SUBPATH = "@o3co/auth-provider-core/reference.conf";

/**
 * Returns the absolute path to the shipped `reference.conf` inside
 * `@o3co/auth-provider-core`. This file is the bottom layer of the
 * 3-tier HOCON precedence chain (reference.conf → application.conf → {env}.conf).
 *
 * Primary path: `import.meta.resolve` (Node.js Stability 1.2 RC, unflagged
 * since Node 18.19.0 / 20.6.0 — well below this scope's Node 22 engine floor,
 * so it is always available). Fallback: `createRequire(import.meta.url).resolve(...)`. The
 * fallback covers two edge cases:
 *
 * 1. A future Node release deprecates or alters the sync form of
 *    `import.meta.resolve` (still labelled Stability 1.2 RC per Node docs).
 * 2. An exotic runtime / loader where `import.meta.resolve` is not
 *    available but CommonJS-style resolution still is.
 *
 * Both APIs read the same `exports` map in `@o3co/auth-provider-core`'s
 * `package.json`, so the resolved path is identical.
 */
export function resolveLibraryReferenceConfPath(): string {
	try {
		return fileURLToPath(import.meta.resolve(REFERENCE_CONF_SUBPATH));
	} catch {
		return createRequire(import.meta.url).resolve(REFERENCE_CONF_SUBPATH);
	}
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
 * Phase one, transitional (#728): what the composition reads before it knows
 * its modules — the switches `buildModules` chooses them by, the log level,
 * `mfa.mode` — from its own files over core's `reference.conf` alone, read
 * with `readTransitionalConfig`. Use it for those choices only: it goes when
 * the switches move into the template's own section, the only one read before
 * the modules are chosen (#728 B5).
 */
export function readSwitches(ownFiles: readonly string[], options: ResolveOptions = {}): AppConfig {
	return readTransitionalConfig(resolveLayers(ownFiles, [coreReference()], options));
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
