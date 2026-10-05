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
 * The one reading of the federations a configuration declares: the map in
 * core's own section, `core.federations`, keyed by each federation's name.
 * Each entry is as written (core's schema coerces its switches), and read as
 * own properties: a key an object inherits is not one anyone wrote. Also the
 * keys core owns on every entry, the rest being its type's, and the rule a
 * federation's name keeps.
 */

/**
 * The keys of an entry core owns — whether it is on, the type that handles
 * it, whether its upstream's `amr` counts, whether its callback alone meets a
 * freshness ask, and where the upstream redirects back to. They are removed
 * before an entry is handed to its type's schema.
 */
export const FEDERATION_ENTRY_CORE_KEYS: readonly string[] = Object.freeze([
	"enabled",
	"type",
	"trustUpstreamAmr",
	"callbackMeetsFreshness",
	"callbackURL",
]);

/** One URL path segment of letters, digits, `.`, `_` and `-`, beginning with a letter or a digit. */
const FEDERATION_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Why `name` cannot name a federation, or `undefined` when it can. A name is
 * the `:name` segment of the federation's routes and the prefix of the
 * identities it links, so it is one plain URL path segment.
 */
export function federationNameProblem(name: string): string | undefined {
	return FEDERATION_NAME.test(name)
		? undefined
		: `a federation's name must be one URL path segment of letters, digits, ".", "_" or "-", beginning with a letter or a digit; got ${JSON.stringify(name)}`;
}

/** The configuration's `core.federations` by name, own entries only; `{}` when it has none. */
export function federationsOf(config: unknown): Readonly<Record<string, unknown>> {
	const core = (config as { core?: unknown } | null | undefined)?.core;
	if (typeof core !== "object" || core === null || !Object.hasOwn(core, "federations")) return {};
	const federations = (core as { federations?: unknown }).federations;
	if (typeof federations !== "object" || federations === null || Array.isArray(federations)) {
		return {};
	}
	return Object.fromEntries(Object.entries(federations));
}

/**
 * The entries of `core.federations` switched on (`enabled` is `true`), by
 * name, in the configuration's key order — JavaScript's: a name that reads as
 * an integer comes first.
 */
export function enabledFederationsOf(config: unknown): readonly (readonly [string, object])[] {
	return Object.entries(federationsOf(config)).filter(
		(pair): pair is [string, object] =>
			typeof pair[1] === "object" &&
			pair[1] !== null &&
			(pair[1] as { readonly enabled?: unknown }).enabled === true,
	);
}
