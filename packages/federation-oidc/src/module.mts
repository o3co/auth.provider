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

import { defineModule, type Module } from "@o3co/auth-provider-core";
import {
	createFederationRedirectPolicy,
	extractFederationSection,
} from "@o3co/auth-provider-session";
import { OIDC_ENTRY_KEYS, oidcEntrySchema } from "./entry.mjs";
import { checkFederationName, createOidcProvider, type OidcProviderConfig } from "./oidc.mjs";
import { OIDC_FEDERATION_TYPE } from "./type-module.mjs";

// ComponentMap slot declaration-merge: one slot holds the config of every
// OIDC instance, keyed by federation name. A composition root fills it —
// `readOidcFederationConfigs` turns the `core.federations` map into
// it — and each `oidcFederationModule(name)` reads its own entry.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/**
		 * @deprecated Read only by the deprecated `oidcFederationModule(name)`.
		 * `oidcFederationTypeModule()` takes each entry from `core.federations`
		 * itself, through core's dispatch by type.
		 */
		readonly oidcFederationConfigs?: Readonly<Record<string, OidcProviderConfig>>;
	}
}

function entryFor(
	configs: Readonly<Record<string, OidcProviderConfig>> | undefined,
	name: string,
): OidcProviderConfig {
	const entry = configs?.[name];
	if (entry === undefined) {
		throw new Error(
			`oidcFederationConfigs has no entry for "${name}" — federation-oidc-${name} is in the manifest, so the composition root must supply its config under that name (readOidcFederationConfigs builds the slot from core.federations)`,
		);
	}
	return entry;
}

/**
 * One module per OIDC instance, a factory unlike the single-tenant
 * Google/GitHub/Apple modules: `oidcFederationModule("okta")` and
 * `oidcFederationModule("keycloak")` each contribute `federations.<name>`
 * (built at boot, discovery included, so a failure refuses boot) and
 * `federationRedirectPolicies.<name>` from their entry in
 * `oidcFederationConfigs`. The name is the `:name` route segment and the
 * prefix of the identity handed to the Store (`<name>:<sub>`). The module
 * name, `federation-oidc-<name>`, is kebab-case only when the federation name
 * is lower-case letters, digits and hyphens.
 *
 * @deprecated Use `oidcFederationTypeModule()`: one module handles every
 * `core.federations` entry of type `oidc`, read from the configuration by
 * core, with no `oidcFederationConfigs` slot to fill. Composing both for one
 * entry refuses boot.
 */
export function oidcFederationModule(name: string): Module {
	checkFederationName(name);
	return defineModule({
		name: `federation-oidc-${name}`,
		requires: ["oidcFederationConfigs"] as const,
		contributes: {
			federations: {
				[name]: (deps) => createOidcProvider(name, entryFor(deps.oidcFederationConfigs, name)),
			},
			federationRedirectPolicies: {
				[name]: (deps) =>
					createFederationRedirectPolicy(entryFor(deps.oidcFederationConfigs, name)),
			},
		},
	});
}

/**
 * Names of every enabled `core.federations.<name>` entry of type `oidc`, sorted.
 *
 * @deprecated Use `oidcFederationTypeModule()`, which core hands every
 * enabled entry of type `oidc`: no composition root lists them.
 */
export function oidcFederationNames(
	federations: Readonly<Record<string, unknown>> | undefined,
): string[] {
	if (!federations) return [];
	return Object.keys(federations)
		.filter((name) => extractFederationSection(federations, name)?.type === OIDC_FEDERATION_TYPE)
		.sort();
}

type Slice = Record<string, unknown>;

/**
 * One entry, read as the type's schema reads it (`entry.mts`) — the one
 * reading both modules share — with its `callbackURL` beside it. Keys the
 * schema does not name are left unread rather than refused: this reader also
 * takes the nested shape, whose outer keys arrive beside the nested ones. A
 * refusal names `core.federations.<name>.<field>`.
 */
function readSection(name: string, slice: Slice): OidcProviderConfig {
	const callbackURL = slice.callbackURL;
	if (typeof callbackURL !== "string" || callbackURL.length === 0) {
		throw new Error(`core.federations.${name}.callbackURL is required (a non-empty string)`);
	}
	const result = oidcEntrySchema.safeParse(
		Object.fromEntries(Object.entries(slice).filter(([key]) => OIDC_ENTRY_KEYS.includes(key))),
	);
	if (!result.success) {
		throw new Error(
			result.error.issues
				.map(
					(issue) =>
						`${["core", "federations", name, ...issue.path.map(String)].join(".")}: ${issue.message}`,
				)
				.join("; "),
		);
	}
	return { ...result.data, callbackURL };
}

/**
 * The `oidcFederationConfigs` slot from the `core.federations` map
 * (`federationsOf`): every enabled entry whose `type` is `oidc`, flat or
 * nested (the shapes `extractFederationSection` accepts), checked field by
 * field so a typo is a boot refusal naming `core.federations.<name>.<field>`. The map has no prototype,
 * and every name is checked before it becomes a key: a section named
 * `__proto__` is refused by name rather than assigned through the prototype
 * setter.
 *
 * @deprecated Use `oidcFederationTypeModule()`, which core hands each
 * enabled entry of type `oidc`, parsed by the type's schema: the slot this
 * fills is read only by the deprecated `oidcFederationModule(name)`.
 */
export function readOidcFederationConfigs(
	federations: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, OidcProviderConfig>> {
	const out: Record<string, OidcProviderConfig> = Object.create(null);
	if (!federations) return out;
	for (const name of oidcFederationNames(federations)) {
		checkFederationName(name);
		const slice = extractFederationSection(federations, name);
		if (!slice) continue;
		out[name] = readSection(name, slice);
	}
	return out;
}
