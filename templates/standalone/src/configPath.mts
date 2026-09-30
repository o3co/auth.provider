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
import type { LoggingSettings } from "./logger.mjs";
import { LOGGING_SECTION, loggingModule } from "./modules.mjs";

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
 * `expectedSessionRequirements` reads (the log level is `readLogging`'s). A
 * module a deployment adds that reads its configuration when it is built adds
 * those paths here, or passes them to `readSwitches` as `reads`.
 * `two-phase-config.test.mts` holds this list and `OWN_READS` to what the
 * template reads.
 *
 * Beside these the template reads `mfa.mode`, the MFA module's key, itself
 * (`OWN_READS`, `readMfaMode`): a composition root reads no module's key, and
 * the template reads this one before it chooses its modules only until it
 * installs the MFA module (the MFA ADR's build order, step 20), which removes
 * this reading.
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
	"federations",
	"federation-grants.enabled",
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

/**
 * What the template reads before it knows its modules and outside `SWITCHES`:
 * `mfa.mode`, the MFA module's key, which core's schema does not declare, read
 * raw from the template's own layers and held to its values by `readMfaMode`.
 * Read only until the template installs the MFA module (the MFA ADR's build
 * order, step 20), which removes this reading.
 */
export const OWN_READS: readonly string[] = ["mfa.mode"];

/** The values `mfa.mode` takes. */
const MFA_MODES = ["off", "optional", "required"] as const;

/** What an `mfa` that is not a section of keys reads as: no mode `readMfaMode` accepts. */
const REFUSED = Symbol("refused");

/** A section of keys: an object whose prototype is `Object.prototype` or none. */
function isPlainSection(value: unknown): value is Readonly<Record<string, unknown>> {
	if (typeof value !== "object" || value === null) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

/** `core.sessionRequirements`, as the composition declares it to boot. */
export type SessionRequirements = NonNullable<AppConfig["core"]>["sessionRequirements"];

/** `mfa.mode`, as `readMfaMode` answers it. */
export type MfaMode = (typeof MFA_MODES)[number];

/**
 * `mfa.mode` as the template reads it before it chooses its modules: raw,
 * off phase one's switches — the template's own layers, where
 * `config/application.conf` binds `MFA_MODE`, since core's `reference.conf`
 * does not — and held to its values here, as the template cannot import the
 * MFA package's schema (it is private). Absent is `off`; anything else is a
 * `RangeError` naming `mfa.mode` that quotes nothing of the value, never read
 * as `off`, which would drop the declaration on a typo.
 *
 * The MFA module's key, which a composition root does not read: the template
 * reads it only until it installs the MFA module (the MFA ADR's build order,
 * step 20), which removes this reading.
 */
export function readMfaMode(switches: unknown): MfaMode {
	const section = (switches as { mfa?: unknown } | undefined)?.mfa;
	if (section === undefined) return "off";
	const mode = isPlainSection(section) ? section.mode : REFUSED;
	if (mode === undefined) return "off";
	const known = MFA_MODES.find((value) => value === mode);
	if (known === undefined) {
		throw new RangeError('mfa.mode must be "off", "optional" or "required"');
	}
	return known;
}

export interface SwitchesOptions {
	/** Paths read beside `SWITCHES`: what a module a deployment adds reads when it is built. */
	readonly reads?: readonly string[];
}

/**
 * Phase one: the switches (`SWITCHES`, and `reads`) from the composition's
 * own layers over core's `reference.conf` alone, read with core's
 * `readTransitionalConfig`: each parsed with the schema core declares at its
 * path, everything else as written. Use it for those choices only. A switch
 * whose default only a package ships reads as unset here; set it in the
 * template's own files.
 */
export function readSwitches(own: OwnLayers, options: SwitchesOptions = {}): AppConfig {
	return readTransitionalConfig(resolveLayers(own, [coreReference()]), [
		...SWITCHES,
		...(options.reads ?? []),
	]);
}

/**
 * The `logging` module's section, read before boot for the logger: the own
 * layers over the module's reference and core's, parsed with the module's
 * schema. A refused value is a `RangeError` naming its path under `logging`.
 */
export function readLogging(own: OwnLayers): LoggingSettings {
	const resolved = resolveLayers(own, moduleReferences([loggingModule]));
	const result = LOGGING_SECTION.safeParse(resolved.logging);
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
 * configuration's `core.sessionRequirements.expected` as written, with `mfa`
 * appended when `mfa.mode` (`readMfaMode`) is not `off` and the list does not
 * name it. Boot's checks never act on `mfa.mode`, and the template installs no
 * MFA module, so it is here that a mode asking for a second factor becomes a
 * declaration boot refuses (`session-requirement-missing`) rather than a
 * composition that logs users in on a password alone. A mode that is none of
 * the three is a `RangeError` naming the key. With no list written and the
 * mode `off`, nothing is declared, and boot's rule for an unwritten key
 * applies. Computed here because HOCON has no conditional. See ADR
 * 2026-09-28-session-admission; the reading of `mfa.mode` goes at the MFA
 * ADR's build-order step 20.
 */
export function expectedSessionRequirements(switches: AppConfig): SessionRequirements {
	const written = switches.core?.sessionRequirements?.expected;
	const mode = readMfaMode(switches);
	if (mode === "off") return written === undefined ? undefined : { expected: [...written] };
	const declared = [...(written ?? [])];
	return { expected: declared.includes("mfa") ? declared : [...declared, "mfa"] };
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

/**
 * Whether `mfa` is only what the template consumed — no key, or the mode
 * alone — with no loaded module owning the section.
 */
const consumedMfa = (mfa: unknown, modules: readonly Module[]): boolean =>
	isPlainSection(mfa) &&
	Object.keys(mfa).every((key) => key === "mode") &&
	!ownsSection(modules, "mfa");

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
 * Refuses, with a `RangeError`, the Redis federation grant store's key prefix
 * moved off its default while the Redis intent store's is left at its
 * default, when `modules` load both. The intent store's prefix is its own key, so a
 * deployment that moved only the grant store's would keep acquisition's
 * records in the default namespace, shared with every deployment on the same
 * Redis database that left it there. The defaults are what the stores'
 * `reference.conf` sets with no environment. The message names both keys and
 * both variables, and quotes neither value.
 */
function refuseIntentPrefixLeftAtDefault(
	resolved: Readonly<Record<string, unknown>>,
	modules: readonly Module[],
): void {
	const grantStore = redisFederationGrantStoreModule;
	const intentStore = redisFederationGrantIntentStoreModule;
	const loaded = (module: Module) => modules.some((m) => m.name === module.name);
	const reference = intentStore.section?.reference;
	if (!loaded(grantStore) || !loaded(intentStore) || reference === undefined) return;
	const defaults = resolveLayers({ config: empty(), env: {} }, [reference]);
	const grant = keyPrefixOf(resolved, grantStore);
	const intent = keyPrefixOf(resolved, intentStore);
	if (grant === undefined || grant === keyPrefixOf(defaults, grantStore)) return;
	if (intent === undefined || intent !== keyPrefixOf(defaults, intentStore)) return;
	const grantKey =
		"redis-federation-grant-store.keyPrefix (REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX)";
	const intentKey =
		"redis-federation-grant-intent-store.keyPrefix (REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX)";
	throw new RangeError(
		`${grantKey} moves the Redis federation grant store off its default key prefix, and ` +
			`${intentKey} is left at its default. The intent store's prefix is its own: ` +
			"acquisition's records would stay in the default namespace, shared with every " +
			`deployment on the same Redis database that left it there. Set ${intentKey} as well — ` +
			"to the grant store's prefix to keep the two together, or to one of its own",
	);
}

/**
 * Phase two: what `createApp` parses once, with every loaded module's schema:
 * the composition's own layers, the same read phase one had, over the
 * `reference.conf` of every package `modules` come from, core's last,
 * resolved and unparsed, with `core.sessionRequirements` — what phase one
 * says the composition expects (`expectedSessionRequirements`) — written over
 * the resolved section when there is one to write. An `mfa` section holding
 * nothing but the mode, which the template read for itself (`readMfaMode`),
 * is left out when no loaded module owns it; anything more reaches boot,
 * which names an unowned section once. The MFA ADR's build-order step 20
 * removes this with the template's reading.
 *
 * Refuses, with a `RangeError`, the Redis federation grant store's key prefix
 * moved while the Redis intent store's is left at its default, both loaded
 * (`refuseIntentPrefixLeftAtDefault`).
 *
 * Typed `AppConfig` because that is the `config` slot's type; read the parsed
 * configuration from `handle.components.config`, not from this.
 */
export function resolveForBoot(
	own: OwnLayers,
	modules: readonly Module[],
	sessionRequirements: SessionRequirements,
): AppConfig {
	const layered = resolveLayers(own, moduleReferences(modules));
	refuseIntentPrefixLeftAtDefault(layered, modules);
	const { mfa: _consumed, ...withoutMfa } = layered;
	const resolved = consumedMfa(layered.mfa, modules) ? withoutMfa : layered;
	return (sessionRequirements === undefined
		? resolved
		: {
				...resolved,
				core: { ...(resolved.core as Record<string, unknown> | undefined), sessionRequirements },
			}) as unknown as AppConfig;
}
