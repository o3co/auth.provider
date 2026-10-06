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
 * a switch at boot. Beside phase two it builds the configuration's defaults,
 * which boot names the sections nothing loaded reads by
 * (`configDefaultsFor`): the same references, with no file of the
 * composition's and no environment.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	type CoreSection,
	coerceBooleanFromEnv,
	type Module,
	moduleReferences,
} from "@o3co/auth-provider-core";
import {
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModule,
} from "@o3co/auth-provider-redis";
import { type Config, empty, parseFile } from "@o3co/ts.hocon";
import { ADAPTERS_SECTION, readAdapters } from "./adapters.mjs";
import {
	configRefused,
	issuesAt,
	keyRefused,
	pathsRelocated,
	sectionPathRefused,
} from "./bootRefusal.mjs";
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

/** `core.sessionRequirements`, as the composition declares it to boot. */
export type SessionRequirements = NonNullable<CoreSection["sessionRequirements"]>;

/**
 * What phase one answers, from the composition's own layers over the
 * template's `config/reference.conf` alone: the composition root's own
 * `adapters` and `mfaMode`, parsed with the template's schema; the Store
 * transport settings — the user repository's HTTP settings,
 * `repositories.user.http`, unparsed — which the Store-backed MFA factor
 * store is built over; and whether the federation-grants modules are
 * installed (`federationGrantsInstalled`). Nothing else of the configuration
 * is read before boot: a module reads its own section, `deps.section`, at
 * boot.
 */
export type Switches = {
	readonly adapters: Adapters;
	readonly mfaMode: MfaSwitch;
	readonly storeTransport: unknown;
	readonly "federation-grants"?: { readonly enabled?: boolean };
};

/**
 * Phase one: from the composition's own layers over the template's
 * `config/reference.conf`, the composition root's own `adapters`
 * (`readAdapters`), which refuses a selection at the path it moved from and a
 * variable renamed with one, its own MFA switch `mfaMode` (`readMfaSwitch`),
 * the Store transport settings, and whether federation grants are installed
 * (`federationGrantsInstalled`). A variable the template bound for a
 * federation it ships, renamed after the entry's path under
 * `core.federations` (`SHIPPED_FEDERATION_RENAMES`), is refused here too.
 * Use it for those choices only. A default only a package's reference ships
 * reads as unset here; the template's own files set what it reads.
 */
export function readSwitches(own: OwnLayers): Switches {
	const template = resolveLayers(own, [templateReference()]);
	const adapters = readAdapters(template, own.env);
	const mfaMode = readMfaSwitch(template, own.env);
	refuseRenamedVariables(own.env, SHIPPED_FEDERATION_RENAMES);
	return {
		adapters,
		mfaMode,
		storeTransport: storeTransportOf(template),
		"federation-grants": { enabled: federationGrantsInstalled(template) },
	};
}

/**
 * Whether `resolved` installs the federation-grants modules: unless
 * `federation-grants.enabled` reads as `false` with core's
 * `coerceBooleanFromEnv`, or is not written at all. A value that does not
 * parse installs them, so that boot refuses it at `federation-grants.enabled`
 * rather than the feature reading as off; so does a section written as
 * something other than a section, and any setting written at the section's
 * old path, `federationGrants`, which boot refuses naming the new path.
 */
function federationGrantsInstalled(resolved: Readonly<Record<string, unknown>>): boolean {
	if (setsAnything(resolved.federationGrants)) return true;
	const section = resolved["federation-grants"];
	if (section === undefined) return false;
	if (!isPlainSection(section)) return true;
	if (section.enabled === undefined) return false;
	const enabled = coerceBooleanFromEnv.safeParse(section.enabled);
	return !(enabled.success && enabled.data === false);
}

/** Whether `value` sets anything: a value, or a section with one somewhere under it. */
function setsAnything(value: unknown): boolean {
	if (value === undefined) return false;
	if (typeof value !== "object" || value === null || Array.isArray(value)) return true;
	return Object.values(value).some(setsAnything);
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
 * schema. A refused value is a `config-validation-failed` `BootError` naming
 * its path under `logging`.
 */
export function readLogging(own: OwnLayers): LoggingSettings {
	const resolved = resolveLayers(own, moduleReferences([loggingModule]));
	const result = loggingSectionSchema.safeParse(resolved.logging);
	if (!result.success) {
		const issues = issuesAt([loggingModule.name], result.error.issues);
		throw configRefused(
			`Config validation failed — ${issues.length} issue(s) found: ${issues
				.map((issue) => `${issue.path.map(String).join(".")}: ${issue.message}`)
				.join("; ")}`,
			issues,
			[{ module: loggingModule.name, schemaPath: loggingModule.name }],
		);
	}
	return result.data;
}

/**
 * What this composition expects of session admission: what to write over
 * the configuration's `core.sessionRequirements` — `written`, as resolved —
 * when the template's MFA switch, `mfaMode`, is not `off`: the configuration's
 * `expected` with `mfa` appended when the list does not name it, and
 * `secondFactorAuthority` written as `mfa` beside it — the switch installs the
 * MFA module, whose requirement registers `mfa` as the second-factor
 * authority, and boot refuses a declared name nothing registers
 * (`session-requirement-missing`) and a declared authority the requirement of
 * that name does not declare. Every other key written there is kept, for
 * boot to refuse. With nothing written, `mfa` alone. With the switch on, a
 * written `secondFactorAuthority` other than `mfa` is a
 * `config-validation-failed` `BootError` naming the key, `mfaMode` and
 * `MFA_MODE`, quoting nothing.
 *
 * `undefined` hands the section on as written: with the switch `off`, and
 * where `written` is not a section or its `expected` is not a list of names,
 * which boot refuses at its path. Computed here because HOCON has no
 * conditional.
 */
export function expectedSessionRequirements(
	written: unknown,
	mfaMode: MfaSwitch,
): SessionRequirements | undefined {
	if (mfaMode === "off") return undefined;
	if (written === undefined) return { expected: ["mfa"], secondFactorAuthority: "mfa" };
	if (!isPlainSection(written)) return undefined;
	const authority = written.secondFactorAuthority;
	if (authority !== undefined && authority !== "mfa") {
		throw keyRefused(
			`core.sessionRequirements.secondFactorAuthority is written and names a requirement other than the one ${MFA_SWITCH} (MFA_MODE) installs as the second-factor authority: remove it, or write mfa`,
			"core",
			["core", "sessionRequirements", "secondFactorAuthority"],
		);
	}
	const declared = written.expected;
	if (!isListOfNames(declared)) return undefined;
	return {
		...written,
		expected: declared.includes("mfa") ? [...declared] : [...declared, "mfa"],
		secondFactorAuthority: "mfa",
	};
}

/** Whether `value` is a list of strings. */
function isListOfNames(value: unknown): value is readonly string[] {
	return Array.isArray(value) && value.every((name) => typeof name === "string");
}

/**
 * Whether a module in `modules` owns the top-level section `name`: its
 * section sits there, at the module's name, or it moved from there or under
 * it.
 */
function ownsSection(modules: readonly Module[], name: string): boolean {
	const topOf = (path: string): string | undefined => path.split(".")[0];
	return modules.some((module) => {
		const section = module.section;
		if (section === undefined) return false;
		if (module.name === name) return true;
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
 * Refuses, with a `BootError`, a Redis intent store left on the default key
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
 * The first is `config-validation-failed` at the intent store's key; the
 * second `config-path-relocated`, from the old key to the intent store's. The
 * defaults are what the package's `reference.conf` sets with no environment.
 * The message names the keys and variables, and quotes no value.
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
	const intentPath = `${intentStore.name}.keyPrefix`;
	const intentVariable = "REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX";
	const intentKey = `${intentPath} (${intentVariable})`;
	const oldSection = resolved.redisFederationGrantStore;
	if (!loaded(grantStore) && isPlainSection(oldSection) && Object.hasOwn(oldSection, "keyPrefix")) {
		throw pathsRelocated(
			"redisFederationGrantStore.keyPrefix is set, and no installed module reads it: the Redis " +
				`intent store's prefix is its own key, ${intentKey}. Set that instead, and delete ` +
				"redisFederationGrantStore.keyPrefix",
			[
				{
					module: intentStore.name,
					from: "redisFederationGrantStore.keyPrefix",
					to: intentPath,
					environmentVariable: intentVariable,
				},
			],
		);
	}
	const defaults = resolveLayers({ config: empty(), env: {} }, [reference]);
	const grant = keyPrefixOf(resolved, grantStore);
	const intent = keyPrefixOf(resolved, intentStore);
	if (grant === undefined || grant === keyPrefixOf(defaults, grantStore)) return;
	if (intent === undefined || intent !== keyPrefixOf(defaults, intentStore)) return;
	const grantKey =
		"redis-federation-grant-store.keyPrefix (REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX)";
	throw keyRefused(
		`${grantKey} is set off its default key prefix, and ${intentKey} is left at its ` +
			"default. The Redis intent store's prefix is its own: acquisition's records would " +
			"stay in the default namespace, shared with every deployment on the same Redis " +
			`database that left it there. Set ${intentKey} as well — to the grant store's prefix ` +
			"to keep the two together, or to one of its own",
		intentStore.name,
		[intentStore.name, "keyPrefix"],
	);
}

/**
 * The composition root's own keys, which phase one consumes and boot is never
 * handed: the `adapters` section and the `mfaMode` switch.
 */
const ROOT_SECTIONS: readonly string[] = [ADAPTERS_SECTION, MFA_SWITCH];

/**
 * Refuses, with a `module-section-path-invalid` `BootError` naming it, a
 * module whose section — at the module's name — is one of the composition
 * root's own sections, which phase one consumes and boot is never handed:
 * the module would read nothing its operator wrote.
 */
function refuseModuleAtRootSections(modules: readonly Module[]): void {
	for (const module of modules) {
		if (module.section === undefined || !ROOT_SECTIONS.includes(module.name)) continue;
		const problem = "the composition root's own section, which boot is not handed, is read there";
		throw sectionPathRefused(
			`Module "${module.name}" has its section at ${module.name}: the composition root's own section, which boot is not handed. Give the module a section of another name.`,
			module.name,
			module.name,
			problem,
		);
	}
}

/**
 * Phase two: what `createApp` parses once, with every loaded module's schema:
 * the composition's own layers, the same read phase one had, over the
 * `reference.conf` of every package `modules` come from, core's last,
 * resolved and unparsed, with `core.sessionRequirements` — what the
 * composition expects under the MFA switch (`expectedSessionRequirements`) —
 * written over the resolved section when there is one to write, and the
 * `mfa` section and the `oauth` acr table as the template's MFA switch
 * decides them (`mfaSectionForBoot`, `oauthForBoot`). Left out: `adapters`
 * and `mfaMode`, the composition root's own keys, which phase one consumed.
 * A section a loaded package's `reference.conf` sets for a module the
 * composition does not load is handed on as resolved: boot tells it apart by
 * the configuration's defaults (`configDefaultsFor`).
 *
 * Refuses, each with a `BootError` (`bootRefusal.mts`), a module whose
 * section is a section of the composition root's
 * (`refuseModuleAtRootSections`), what
 * `expectedSessionRequirements` refuses of `core.sessionRequirements`, what
 * `mfaSectionForBoot` refuses of the `mfa` section, and the Redis intent
 * store left on its default key prefix where the grant store's was moved
 * (`refuseIntentPrefixLeftAtDefault`).
 *
 * Typed `AppConfig` because that is the `config` slot's type; read the parsed
 * configuration from `handle.components.config`, not from this.
 */
export function resolveForBoot(
	own: OwnLayers,
	modules: readonly Module[],
	switches: Pick<Switches, "mfaMode" | "adapters">,
): AppConfig {
	refuseModuleAtRootSections(modules);
	const all = resolveLayers(own, moduleReferences(modules));
	refuseIntentPrefixLeftAtDefault(all, modules);
	const layered = Object.fromEntries(
		Object.entries(all).filter(([name]) => !ROOT_SECTIONS.includes(name)),
	);
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
	// `core` written as something other than a section is handed on as
	// written, for boot to refuse.
	const core = isPlainSection(resolved.core) ? resolved.core : undefined;
	const sessionRequirements =
		resolved.core === undefined || core !== undefined
			? expectedSessionRequirements(core?.sessionRequirements, switches.mfaMode)
			: undefined;
	return {
		...resolved,
		...(mfa === undefined ? {} : { mfa }),
		...(resolved.oauth === undefined
			? {}
			: { oauth: oauthForBoot(switches.mfaMode, resolved.oauth) }),
		...(sessionRequirements === undefined ? {} : { core: { ...core, sessionRequirements } }),
	} as unknown as AppConfig;
}

/**
 * The configuration's defaults, which boot names the sections nothing loaded
 * reads by (`bootstrapComponents.configDefaults`): the `reference.conf` of
 * every package `modules` come from, layered as `resolveForBoot` layers them
 * (core's last), with no file of the composition's and no environment.
 */
export function configDefaultsFor(modules: readonly Module[]): Record<string, unknown> {
	return resolveLayers({ config: empty(), env: {} }, moduleReferences(modules));
}
