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
 * Where the template's configuration comes from: the composition's own layers
 * (`{env}.conf` over `application.conf`), read once by `readOwnLayers` under
 * one snapshot of the environment, and what is built from that read: the two
 * phases, `readSwitches` and `resolveForBoot`, and the `logging` module's
 * section the logger is built from, `readLogging` (template README,
 * "Environment-specific config overlay"). So a file or variable changed
 * during startup cannot split a switch phase one reads from the value boot's
 * parse has, which matters because adapter selections have no disagreement
 * guard at boot; `two-phase-config.test.mts` pins this for the shipped
 * environments. A loaded module's own schema may still make something else of
 * a switch at boot.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
	type AppConfig,
	coreReference,
	type Module,
	moduleReferences,
	readTransitionalConfig,
} from "@o3co/auth-provider-core";
import {
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModule,
} from "@o3co/auth-provider-redis";
import { type Config, empty, parseFile } from "@o3co/ts.hocon";
import { ADAPTERS_SECTION, readAdapters } from "./adapters.mjs";
import { MFA_SWITCH, mfaSectionForBoot, oauthForBoot, readMfaSwitch } from "./mfaSwitch.mjs";
import { loggingModule, templateReference } from "./modules.mjs";
import { refuseRenamedVariables, SHIPPED_FEDERATION_RENAMES } from "./rootRenames.mjs";
import {
	type Adapters,
	isPlainSection,
	type LoggingSettings,
	loggingSectionSchema,
	type MfaSwitch,
} from "./sections.mjs";

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
 * The composition's own layers, read once: its files parsed, and the
 * environment snapshot every layer's `${?VAR}` substitutes. Both phases are
 * built from this one read.
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
 * nothing: its own layers, read once (`readOwnLayers`), over
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
 * What the template reads before it knows its modules, through core's
 * reader: the switches `buildModules` and its module factories choose by, and
 * the configuration's `core.sessionRequirements`, which
 * `expectedSessionRequirements` reads (the log level is `readLogging`'s).
 * No federation entry is among them: the template loads the federation types
 * it bundles whatever `core.federations` says, and boot dispatches each
 * enabled entry to its type. A module a deployment adds that reads its
 * configuration when it is built adds those paths here, or passes them to
 * `readSwitches` as `reads`.
 * `two-phase-config.test.mts` holds this list to what the template reads.
 *
 * Every path here and in `reads` must be one core's transitional base
 * declares (a section core's schema has, or mirrors for a package), or
 * `readSwitches` refuses it. A deployment module reading, when it is built, a
 * key of its own that core does not mirror gets it as written: raw, an
 * environment variable's string and all, without what only a package's
 * `reference.conf` sets. Parse it in the module, or read it after boot.
 */
export const SWITCHES: readonly string[] = [
	"core.sessionRequirements",
	"federation-grants.enabled",
	"session-store.storage",
	"oauth-session.enabled",
	"oauth-authorization.grants",
	"oauth.accessToken",
];

/** `core.sessionRequirements`, as the composition declares it to boot. */
export type SessionRequirements = NonNullable<AppConfig["core"]>["sessionRequirements"];

export interface SwitchesOptions {
	/** Paths read beside `SWITCHES`: what a module a deployment adds reads when it is built. */
	readonly reads?: readonly string[];
}

/**
 * What phase one answers: the switches core's reader parsed; the composition
 * root's own `adapters` and `mfaMode`, parsed with the template's schema;
 * and the Store transport settings — the user repository's HTTP settings,
 * `repositories.user.http`, as the template's own layers hold them, unparsed
 * — which the Store-backed MFA factor store is built over.
 */
export type Switches = AppConfig & {
	readonly adapters: Adapters;
	readonly mfaMode: MfaSwitch;
	readonly storeTransport: unknown;
};

/**
 * Phase one: the switches (`SWITCHES`, and `reads`) from the composition's
 * own layers over core's `reference.conf` alone, read with core's
 * `readTransitionalConfig`: each parsed with the schema core declares at its
 * path, everything else as written; and, from its own layers over the
 * template's `config/reference.conf`, the composition root's own `adapters`
 * (`readAdapters`), which refuses a selection at the path it moved from and a
 * variable renamed with one, its own MFA switch `mfaMode` (`readMfaSwitch`),
 * and the Store transport settings. A variable the template bound for a
 * federation it ships, renamed after the entry's path under
 * `core.federations` (`SHIPPED_FEDERATION_RENAMES`), is refused here too.
 * Use it for those choices only. A switch whose
 * default only a package ships reads as unset here; set it in the template's
 * own files.
 */
export function readSwitches(own: OwnLayers, options: SwitchesOptions = {}): Switches {
	const template = resolveLayers(own, [templateReference()]);
	const adapters = readAdapters(template, own.env);
	const mfaMode = readMfaSwitch(template, own.env);
	refuseRenamedVariables(own.env, SHIPPED_FEDERATION_RENAMES);
	const switches = readTransitionalConfig(resolveLayers(own, [coreReference()]), [
		...SWITCHES,
		...(options.reads ?? []),
	]);
	return { ...switches, adapters, mfaMode, storeTransport: storeTransportOf(template) };
}

/** `repositories.user.http` in `resolved`, as written; `undefined` when absent. */
function storeTransportOf(resolved: Readonly<Record<string, unknown>>): unknown {
	const repositories = resolved.repositories;
	const user = isPlainSection(repositories) ? repositories.user : undefined;
	return isPlainSection(user) ? user.http : undefined;
}

/**
 * The `logging` module's section, read before boot for the logger: the own
 * layers over the module's reference and core's, parsed with the module's
 * schema. A refused value is a `RangeError` naming its path under `logging`.
 */
export function readLogging(own: OwnLayers): LoggingSettings {
	const resolved = resolveLayers(own, moduleReferences([loggingModule]));
	const result = loggingSectionSchema.safeParse(resolved.logging);
	if (!result.success) {
		const issues = result.error.issues;
		throw new RangeError(
			`Config validation failed — ${issues.length} issue(s) found: ${issues
				.map((issue) => `${["logging", ...issue.path.map(String)].join(".")}: ${issue.message}`)
				.join("; ")}`,
			{ cause: result.error },
		);
	}
	return result.data;
}

/**
 * What this composition expects of session admission, from phase one: the
 * configuration's `core.sessionRequirements` as written, with `mfa` appended
 * to `expected` when the template's MFA switch, `mfaMode`, is not `off` and
 * the list does not name it, and `secondFactorAuthority` written as `mfa`
 * beside it — the switch installs the MFA module, whose requirement registers
 * `mfa` as the second-factor authority, and boot refuses a declared name
 * nothing registers (`session-requirement-missing`) and a declared authority
 * the requirement of that name does not declare. With the switch on, a
 * written `secondFactorAuthority` other than `mfa` is a `RangeError` naming
 * the key, `mfaMode` and `MFA_MODE`, quoting nothing. With the switch `off`
 * the section is as written, and with nothing written nothing is declared:
 * boot's rule for an unwritten key applies. Computed here because HOCON has
 * no conditional.
 */
export function expectedSessionRequirements(
	switches: Pick<Switches, "core" | "mfaMode">,
): SessionRequirements {
	const written = switches.core?.sessionRequirements;
	if (switches.mfaMode === "off") {
		return written === undefined ? undefined : { ...written, expected: [...written.expected] };
	}
	const authority = written?.secondFactorAuthority;
	if (authority !== undefined && authority !== "mfa") {
		throw new RangeError(
			`core.sessionRequirements.secondFactorAuthority is written and names a requirement other than the one ${MFA_SWITCH} (MFA_MODE) installs as the second-factor authority: remove it, or write mfa`,
		);
	}
	const declared = [...(written?.expected ?? [])];
	return {
		expected: declared.includes("mfa") ? declared : [...declared, "mfa"],
		secondFactorAuthority: "mfa",
	};
}

/**
 * Whether a module in `modules` owns the top-level section `name`: its
 * section sits there or under it, or it moved from there or under it.
 */
function ownsSection(modules: readonly Module[], name: string): boolean {
	const topOf = (path: string): string | undefined => path.split(".")[0];
	return modules.some((module) => {
		const section = module.section;
		if (section === undefined) return false;
		if ((section.at === undefined ? module.name : topOf(section.at)) === name) return true;
		const from = section.relocatedFrom;
		const old = from === undefined ? [] : Array.isArray(from) ? from : Object.keys(from);
		return old.some((path) => topOf(path) === name);
	});
}

/** A section's `keyPrefix`, when the section is one of keys and the prefix a string. */
function keyPrefixOf(
	config: Readonly<Record<string, unknown>>,
	module: Module,
): string | undefined {
	const section = config[module.name];
	const prefix = isPlainSection(section) ? section.keyPrefix : undefined;
	return typeof prefix === "string" ? prefix : undefined;
}

/**
 * Refuses, with a `RangeError`, a Redis intent store left on the default key
 * prefix where the grant store's was moved, when `modules` load the Redis
 * intent store. The intent store's prefix is its own key, so a deployment
 * that moved only the grant store's would keep acquisition's records in the
 * default namespace, shared with every deployment on the same Redis database
 * that left it there. Refused:
 *
 * - `redis-federation-grant-store.keyPrefix` off its default while
 *   `redis-federation-grant-intent-store.keyPrefix` is at its own, whether or
 *   not the Redis grant store is loaded: the package's `reference.conf`, which
 *   binds both, is layered with the intent store;
 * - with the Redis grant store not loaded, `redisFederationGrantStore.keyPrefix`
 *   written at all: the intent store read that key, and no loaded module
 *   relocates it.
 *
 * The defaults are what the package's `reference.conf` sets with no
 * environment. The message names the keys and variables, and quotes no value.
 */
function refuseIntentPrefixLeftAtDefault(
	resolved: Readonly<Record<string, unknown>>,
	modules: readonly Module[],
): void {
	const grantStore = redisFederationGrantStoreModule;
	const intentStore = redisFederationGrantIntentStoreModule;
	const loaded = (module: Module) => modules.some((m) => m.name === module.name);
	const reference = intentStore.section?.reference;
	if (!loaded(intentStore) || reference === undefined) return;
	const intentKey =
		"redis-federation-grant-intent-store.keyPrefix (REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX)";
	const oldSection = resolved.redisFederationGrantStore;
	if (!loaded(grantStore) && isPlainSection(oldSection) && Object.hasOwn(oldSection, "keyPrefix")) {
		throw new RangeError(
			"redisFederationGrantStore.keyPrefix is set, and no installed module reads it: the Redis " +
				`intent store's prefix is its own key, ${intentKey}. Set that instead, and delete ` +
				"redisFederationGrantStore.keyPrefix",
		);
	}
	const defaults = resolveLayers({ config: empty(), env: {} }, [reference]);
	const grant = keyPrefixOf(resolved, grantStore);
	const intent = keyPrefixOf(resolved, intentStore);
	if (grant === undefined || grant === keyPrefixOf(defaults, grantStore)) return;
	if (intent === undefined || intent !== keyPrefixOf(defaults, intentStore)) return;
	const grantKey =
		"redis-federation-grant-store.keyPrefix (REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX)";
	throw new RangeError(
		`${grantKey} is set off its default key prefix, and ${intentKey} is left at its ` +
			"default. The Redis intent store's prefix is its own: acquisition's records would " +
			"stay in the default namespace, shared with every deployment on the same Redis " +
			`database that left it there. Set ${intentKey} as well — to the grant store's prefix ` +
			"to keep the two together, or to one of its own",
	);
}

/**
 * The composition root's own keys, which phase one consumes and boot is never
 * handed: the `adapters` section and the `mfaMode` switch.
 */
const ROOT_SECTIONS: readonly string[] = [ADAPTERS_SECTION, MFA_SWITCH];

/**
 * The sections the template's own `config/reference.conf` sets that no module
 * in `modules` owns and that nothing has changed: as that file sets them with
 * no environment. Boot is not handed them, so a module of the template's the
 * composition does not load names nothing at boot; a section an operator's
 * layer or the environment changed is handed on, and boot names it once as a
 * section nothing owns.
 */
function unownedTemplateDefaults(
	resolved: Readonly<Record<string, unknown>>,
	modules: readonly Module[],
): readonly string[] {
	const defaults = resolveLayers({ config: empty(), env: {} }, [templateReference()]);
	return Object.keys(defaults).filter(
		(name) =>
			name !== RENAMED_VARIABLES &&
			!ROOT_SECTIONS.includes(name) &&
			!ownsSection(modules, name) &&
			isDeepStrictEqual(resolved[name], defaults[name]),
	);
}

/**
 * Refuses, with a `RangeError` naming it, a module whose section is at or
 * under one of the composition root's own sections, which phase one consumes
 * and boot is never handed: the module would read nothing its operator wrote.
 */
function refuseModuleAtRootSections(modules: readonly Module[]): void {
	for (const module of modules) {
		const section = module.section;
		if (section === undefined) continue;
		const path = section.at ?? module.name;
		const top = path.split(".")[0] ?? path;
		if (ROOT_SECTIONS.includes(top)) {
			throw new RangeError(
				`Module "${module.name}" has its section at ${path}, under ${top}: the composition root's own section, which boot is not handed. Give the module a section of another name.`,
			);
		}
	}
}

/** The section a resolution captures renamed variables in: never left out. */
const RENAMED_VARIABLES = "renamed-variables";

/**
 * Phase two: what `createApp` parses once, with every loaded module's schema:
 * the composition's own layers, the same read phase one had, over the
 * `reference.conf` of every package `modules` come from, core's last,
 * resolved and unparsed, with `core.sessionRequirements` — what phase one
 * says the composition expects (`expectedSessionRequirements`) — written over
 * the resolved section when there is one to write, and the `mfa` section and
 * the `oauth` acr table as the template's MFA switch decides them
 * (`mfaSectionForBoot`, `oauthForBoot`). Left out:
 * `adapters` and `mfaMode`, the composition root's own keys, which phase one
 * consumed, and a section the template's own `reference.conf` sets for a
 * module the composition does not load, left as that file sets it
 * (`unownedTemplateDefaults`).
 *
 * Refuses, with a `RangeError`, a module whose section is under a section of
 * the composition root's (`refuseModuleAtRootSections`), what
 * `mfaSectionForBoot` refuses of the `mfa` section, and the Redis intent store left
 * on its default key prefix where the grant store's was moved
 * (`refuseIntentPrefixLeftAtDefault`).
 *
 * Typed `AppConfig` because that is the `config` slot's type; read the parsed
 * configuration from `handle.components.config`, not from this.
 */
export function resolveForBoot(
	own: OwnLayers,
	modules: readonly Module[],
	switches: Pick<Switches, "core" | "mfaMode" | "adapters">,
): AppConfig {
	refuseModuleAtRootSections(modules);
	const all = resolveLayers(own, moduleReferences(modules));
	refuseIntentPrefixLeftAtDefault(all, modules);
	const unowned = new Set([...ROOT_SECTIONS, ...unownedTemplateDefaults(all, modules)]);
	const layered = Object.fromEntries(Object.entries(all).filter(([name]) => !unowned.has(name)));
	const { mfa: _decided, ...resolved } = layered;
	const mfa = mfaSectionForBoot({
		mode: switches.mfaMode,
		written: (own.config.toObject() as Record<string, unknown>).mfa,
		resolved: all,
		owned: ownsSection(modules, "mfa"),
		storeCalled:
			switches.adapters.userRepository === "http" || switches.adapters.mfaFactorStore === "store",
		env: own.env,
	});
	const sessionRequirements = expectedSessionRequirements(switches);
	return {
		...resolved,
		...(mfa === undefined ? {} : { mfa }),
		...(resolved.oauth === undefined
			? {}
			: { oauth: oauthForBoot(switches.mfaMode, resolved.oauth) }),
		...(sessionRequirements === undefined
			? {}
			: {
					core: { ...(resolved.core as Record<string, unknown> | undefined), sessionRequirements },
				}),
	} as unknown as AppConfig;
}
