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
 * The template's MFA switch, the composition root's own key `mfaMode`
 * (`MFA_MODE`), `required` unless set otherwise: reading it before the
 * modules are chosen, the modules it installs, and what it hands boot of the
 * MFA module's section. Off installs nothing of MFA and hands boot nothing of
 * it; on installs the MFA package's modules over the two MFA stores
 * `adapters` selects.
 *
 * Refuses, each before boot with a `config-validation-failed` `BootError`
 * (`bootRefusal.mts`) that names the keys and variables and quotes no value
 * of a mode, a timeout or a key:
 * - a switch outside its three values, or a file's `mfaMode` that `MFA_MODE`
 *   contradicts (`readMfaSwitch`);
 * - an MFA store kept in memory with MFA on, unless every environment name
 *   it reads says development or test (`mfaModulesFor`) — the first refusal a
 *   deployment that sets nothing about MFA meets outside development, so it
 *   also names what MFA needs there and `MFA_MODE=off`;
 * - an `mfa.mode` the configuration writes that the switch does not say;
 *   `MFA_ENCRYPTION_KEY` set beside a ring that holds the development sample
 *   key in its place; and `mfa.storeTimeoutMs` below the user directory's
 *   timeout where the Store is called (`mfaSectionForBoot`).
 */

import {
	type Module,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	productionEnvironmentIn,
	readEnvironmentName,
} from "@o3co/auth-provider-core";
import { foundationMfaFactorStoreModule } from "@o3co/auth-provider-foundation";
import { MFA_DEVELOPMENT_SAMPLE_KEY, mfaModules, mfaResetModule } from "@o3co/auth-provider-mfa";
import {
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
} from "@o3co/auth-provider-redis";
import { loginCompletionModule } from "@o3co/auth-provider-session";
import { ADAPTERS_SECTION } from "./adapters.mjs";
import { configRefused, customIssue, issuesAt, keyRefused } from "./bootRefusal.mjs";
import { type Adapters, isPlainSection, type MfaSwitch, mfaSwitchSchema } from "./sections.mjs";

/** The composition root's MFA switch, a key of its own. No module may be named after it. */
export const MFA_SWITCH = "mfaMode";

/** The MFA module's section, which the switch decides. */
const MFA_SECTION = "mfa";

/** The `acr` the template advertises while MFA is on, met by a verified second factor. */
const MFA_ACR = "urn:o3co:acr:mfa";

/**
 * `mfaMode` from `resolved` — the template's own layers over its
 * `config/reference.conf` — parsed with the template's schema, under `env`,
 * the environment the layers were substituted with. A value the schema
 * refuses, or `MFA_MODE` set to other than what a file writes over it, is a
 * `config-validation-failed` `BootError` naming `mfaMode` and `MFA_MODE`.
 */
export function readMfaSwitch(
	resolved: Readonly<Record<string, unknown>>,
	env: Readonly<Record<string, string>>,
): MfaSwitch {
	const result = mfaSwitchSchema.safeParse(resolved[MFA_SWITCH]);
	if (!result.success) {
		throw configRefused(
			`Config validation failed — ${MFA_SWITCH} (MFA_MODE): ${result.error.issues
				.map((issue) => issue.message)
				.join("; ")}`,
			issuesAt([MFA_SWITCH], result.error.issues),
			[{ module: MFA_SWITCH, schemaPath: MFA_SWITCH }],
		);
	}
	const variable = env.MFA_MODE;
	if (variable !== undefined && variable !== result.data) {
		throw keyRefused(
			`MFA_MODE is set and differs from ${MFA_SWITCH}, which a configuration file writes over it: the file, not the variable, would decide whether MFA is installed. Remove ${MFA_SWITCH} from the file, or set MFA_MODE to what it says`,
			MFA_SWITCH,
			[MFA_SWITCH],
		);
	}
	return result.data;
}

/** The names the memory MFA stores are let in under. */
const DEVELOPMENT_NAMES: ReadonlySet<string> = new Set(["development", "test"]);

/**
 * Why the MFA stores may not be kept in memory under `environment` and
 * `CONFIG_ENV` and `NODE_ENV` wherever they are set: each name that is not
 * development or test, or that nothing is named. None lifts another's.
 */
function memoryRefusals(environment: string | undefined): string[] {
	const named: [string, string][] =
		environment === undefined ? [] : [["the environment", environment]];
	for (const variable of ["CONFIG_ENV", "NODE_ENV"] as const) {
		const value = process.env[variable];
		if (readEnvironmentName(value) !== undefined) named.push([variable, value as string]);
	}
	if (named.length === 0) return ["no environment is named"];
	return named.flatMap(([label, value]) => {
		const production = productionEnvironmentIn([value]);
		if (production !== undefined) return [`${label} is "${production}"`];
		const name = readEnvironmentName(value) ?? "";
		return DEVELOPMENT_NAMES.has(name) ? [] : [`${label} "${name}" is not development or test`];
	});
}

/**
 * The modules the switch installs: none under `off`; otherwise the MFA
 * package's (`mfaModules`, `mfaResetModule`), the session package's
 * `loginCompletionModule`, and the two MFA stores `adapters` selects — on
 * Redis, in the Store over `storeTransport` (the factors only), or in memory.
 * A store in memory loses every factor, lock, hold and recorded email proof
 * at a restart, after which whoever holds a password can bind a factor of
 * their own: it is refused, naming each such setting and its variable,
 * unless `environment`, and `CONFIG_ENV` and `NODE_ENV` where set, each say
 * development or test. Under `core.deployment.mode = "multi"` core refuses
 * the memory stores by name as well.
 */
export function mfaModulesFor(options: {
	readonly mode: MfaSwitch;
	readonly adapters: Pick<Adapters, "mfaFactorStore" | "mfaTransactionStore">;
	readonly storeTransport: unknown;
	readonly environment: string | undefined;
}): Module[] {
	if (options.mode === "off") return [];
	const { adapters, environment } = options;
	const inMemory = (
		[
			["mfaFactorStore", "ADAPTERS_MFA_FACTOR_STORE"],
			["mfaTransactionStore", "ADAPTERS_MFA_TRANSACTION_STORE"],
		] as const
	).filter(([key]) => adapters[key] === "memory");
	const reasons = inMemory.length === 0 ? [] : memoryRefusals(environment);
	if (reasons.length > 0) {
		const refused = `"memory", refused because ${reasons.join(" and ")}`;
		const settings = inMemory
			.map(([key, variable]) => `${ADAPTERS_SECTION}.${key} (${variable})`)
			.join(" and ");
		throw configRefused(
			`MFA is on (${MFA_SWITCH}, MFA_MODE, which installs it unless set to off) and ${settings} ${inMemory.length === 1 ? "is" : "are"} ${refused}: a store in memory loses every factor, lock and recorded email proof at a restart, after which whoever holds a password can bind a factor of their own. Select "redis" (or, for the factors, "store"); memory is for development and test alone. Outside development MFA also needs MFA_ENCRYPTION_KEY, the SMTP relay (STANDARD_SMTP_MAIL_SENDER_HOST and STANDARD_SMTP_MAIL_SENDER_FROM) or your own mail sender, and an MFA page served at MFA_PAGE_URL. A deployment that wants no MFA sets MFA_MODE=off`,
			inMemory.map(([key, variable]) =>
				customIssue(
					[ADAPTERS_SECTION, key],
					`${variable} is ${refused}, with MFA on (${MFA_SWITCH}, MFA_MODE)`,
				),
			),
			[{ module: ADAPTERS_SECTION, schemaPath: ADAPTERS_SECTION }],
		);
	}
	return [
		adapters.mfaFactorStore === "redis"
			? redisMfaFactorStoreModule
			: adapters.mfaFactorStore === "store"
				? foundationMfaFactorStoreModule({ storeTransport: options.storeTransport })
				: memoryMfaFactorStoreModule,
		adapters.mfaTransactionStore === "redis"
			? redisMfaTransactionStoreModule
			: memoryMfaTransactionStoreModule,
		...mfaModules(environment === undefined ? {} : { environment }),
		mfaResetModule,
		loginCompletionModule,
	];
}

/** A whole number as configuration carries one: a number, or an environment variable's digits. */
function wholeNumber(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isInteger(value)) return value;
	return typeof value === "string" && /^\d+$/.test(value) ? Number(value) : undefined;
}

/** The value at `path` of `tree`, through sections of keys alone. */
function valueAt(tree: unknown, path: readonly string[]): unknown {
	let cursor: unknown = tree;
	for (const key of path) {
		if (!isPlainSection(cursor)) return undefined;
		cursor = cursor[key];
	}
	return cursor;
}

/**
 * What boot is handed of the `mfa` section under the switch `mode`;
 * `undefined` hands none. None unless a loaded module owns it (`owned`):
 * what the configuration writes there — `config/development.conf`'s key ring
 * included — sets nothing while the switch installs no MFA. Owned, it is
 * `resolved`'s section, with `mfa.mode` written from the switch when the
 * switch installs MFA. Refuses (see the file header), whatever the switch, an
 * `mfa.mode` the composition's own layers (`written`, their `mfa`) write that
 * the switch does not say, or an `mfa` written as a value; with MFA on, a
 * ring holding the development sample key while `MFA_ENCRYPTION_KEY` names
 * another, and, where the Store is called (`storeCalled`), `mfa.storeTimeoutMs`
 * below `repositories.user.http.timeout`.
 */
export function mfaSectionForBoot(options: {
	readonly mode: MfaSwitch;
	readonly written: unknown;
	readonly resolved: Readonly<Record<string, unknown>>;
	readonly owned: boolean;
	readonly storeCalled: boolean;
	readonly env: Readonly<Record<string, string>>;
}): unknown {
	const { mode, written, resolved } = options;
	if (written !== undefined && !isPlainSection(written)) {
		throw keyRefused(
			`mfa is written as a value in the configuration; it is the MFA package's section, and ${MFA_SWITCH} (MFA_MODE) decides whether the template installs MFA. Remove mfa, and set MFA_MODE or ${MFA_SWITCH}`,
			MFA_SECTION,
			[MFA_SECTION],
		);
	}
	const writtenMode = written === undefined ? undefined : written.mode;
	if (writtenMode !== undefined && writtenMode !== mode) {
		throw keyRefused(
			`mfa.mode is written in the configuration and differs from ${MFA_SWITCH} (MFA_MODE), which decides whether the template installs MFA and writes mfa.mode from it. Set MFA_MODE or ${MFA_SWITCH}, and remove mfa.mode`,
			MFA_SECTION,
			[MFA_SECTION, "mode"],
		);
	}
	if (!options.owned) return undefined;
	const section = resolved[MFA_SECTION];
	if (mode === "off" || !isPlainSection(section)) return section;
	// Exported but blank names no key.
	const variableKey = options.env.MFA_ENCRYPTION_KEY?.trim() ?? "";
	const ring = Array.isArray(section.encryptionKeys) ? section.encryptionKeys : [];
	if (
		variableKey !== "" &&
		variableKey !== MFA_DEVELOPMENT_SAMPLE_KEY &&
		ring.some((entry) => valueAt(entry, ["key"]) === MFA_DEVELOPMENT_SAMPLE_KEY)
	) {
		throw keyRefused(
			"MFA_ENCRYPTION_KEY is set, and mfa.encryptionKeys holds the development sample key in its place: a ring a configuration file writes (config/development.conf's) wins over the variable, so the key you set would seal nothing. Write your key in place of the sample key in that ring, or unset MFA_ENCRYPTION_KEY",
			MFA_SECTION,
			[MFA_SECTION, "encryptionKeys"],
		);
	}
	const storeTimeout = wholeNumber(section.storeTimeoutMs);
	const userTimeout = wholeNumber(valueAt(resolved, ["repositories", "user", "http", "timeout"]));
	if (
		options.storeCalled &&
		storeTimeout !== undefined &&
		userTimeout !== undefined &&
		storeTimeout < userTimeout
	) {
		throw keyRefused(
			"mfa.storeTimeoutMs (MFA_STORE_TIMEOUT_MS) is below repositories.user.http.timeout (REPOSITORIES_USER_HTTP_TIMEOUT): one MFA Store call's time must cover the Store's own per-call timeout, or a factor-set write's lease can lapse while a Store call is still running. Raise MFA_STORE_TIMEOUT_MS to at least the user directory's timeout",
			MFA_SECTION,
			[MFA_SECTION, "storeTimeoutMs"],
		);
	}
	return { ...section, mode };
}

/**
 * `oauth` with `urn:o3co:acr:mfa = ["mfa"]` added to its `acr` table while
 * the switch installs MFA, unless the configuration writes that entry
 * itself; as it is otherwise, so a composition without MFA advertises
 * exactly what it would without the switch.
 */
export function oauthForBoot(mode: MfaSwitch, oauth: unknown): unknown {
	if (mode === "off" || !isPlainSection(oauth)) return oauth;
	const authorize = oauth.authorize ?? {};
	const acrValues = isPlainSection(authorize) ? (authorize.acrValues ?? {}) : undefined;
	// A shape the oauth module's schema refuses is left for it to name.
	if (!isPlainSection(authorize) || !isPlainSection(acrValues)) return oauth;
	if (Object.hasOwn(acrValues, MFA_ACR)) return oauth;
	return {
		...oauth,
		authorize: { ...authorize, acrValues: { ...acrValues, [MFA_ACR]: ["mfa"] } },
	};
}
