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
import type { OidcPrivateKey } from "./client-auth.mjs";
import {
	checkFederationName,
	createOidcProvider,
	type OidcEndpointOverrides,
	type OidcProviderConfig,
} from "./oidc.mjs";

// ComponentMap slot declaration-merge: one slot holds the config of every
// OIDC instance, keyed by federation name. A composition root fills it —
// `readOidcFederationConfigs` turns the `federations` config section into
// it — and each `oidcFederationModule(name)` reads its own entry.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly oidcFederationConfigs?: Readonly<Record<string, OidcProviderConfig>>;
	}
}

/** The `type` a `federations.<name>` section names to select this provider. */
export const OIDC_FEDERATION_TYPE = "oidc";

function entryFor(
	configs: Readonly<Record<string, OidcProviderConfig>> | undefined,
	name: string,
): OidcProviderConfig {
	const entry = configs?.[name];
	if (entry === undefined) {
		throw new Error(
			`oidcFederationConfigs has no entry for "${name}" — federation:oidc:${name} is in the manifest, so the composition root must supply its config under that name (readOidcFederationConfigs builds the slot from config.federations)`,
		);
	}
	return entry;
}

/**
 * One module per OIDC instance (#524).
 *
 * Unlike the single-tenant Google/GitHub/Apple modules this is a factory:
 * a deployment brokering login to two issuers lists
 * `oidcFederationModule("okta")` and `oidcFederationModule("keycloak")`,
 * and each contributes `federations.<name>` (the provider, built at boot —
 * discovery included, so a failure refuses boot) and
 * `federationRedirectPolicies.<name>` from its entry in
 * `oidcFederationConfigs`. The name is the `:name` route segment and the
 * prefix of the identity handed to the Store (`<name>:<sub>`).
 */
export function oidcFederationModule(name: string): Module {
	checkFederationName(name);
	return defineModule({
		name: `federation:oidc:${name}`,
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

/** Names of every enabled `federations.<name>` section of type `oidc`, sorted. */
export function oidcFederationNames(federations: Record<string, unknown> | undefined): string[] {
	if (!federations) return [];
	return Object.keys(federations)
		.filter((name) => extractFederationSection(federations, name)?.type === OIDC_FEDERATION_TYPE)
		.sort();
}

type Slice = Record<string, unknown>;

const ENDPOINT_KEYS: ReadonlyArray<keyof OidcEndpointOverrides> = [
	"authorizationEndpoint",
	"tokenEndpoint",
	"jwksUri",
	"userinfoEndpoint",
	"endSessionEndpoint",
];

const isObject = (value: unknown): value is Slice =>
	typeof value === "object" && value !== null && !Array.isArray(value);

function readSection(name: string, slice: Slice): OidcProviderConfig {
	const at = (field: string): string => `federations.${name}.${field}`;
	const present = (field: string): boolean => slice[field] !== undefined && slice[field] !== null;

	const requiredString = (field: string): string => {
		const value = slice[field];
		if (typeof value !== "string" || value.length === 0) {
			throw new Error(`${at(field)} is required (a non-empty string)`);
		}
		return value;
	};
	const optionalString = (field: string): string | undefined => {
		if (!present(field)) return undefined;
		const value = slice[field];
		if (typeof value !== "string") throw new Error(`${at(field)} must be a string when present`);
		return value;
	};
	const optionalBoolean = (field: string): boolean | undefined => {
		if (!present(field)) return undefined;
		const value = slice[field];
		if (typeof value === "boolean") return value;
		if (value === "true") return true;
		if (value === "false") return false;
		throw new Error(`${at(field)} must be true or false`);
	};
	const optionalNumber = (field: string): number | undefined => {
		if (!present(field)) return undefined;
		const value = slice[field];
		if (typeof value !== "number" || !Number.isFinite(value)) {
			throw new Error(`${at(field)} must be a number`);
		}
		return value;
	};
	const optionalStringList = (field: string): readonly string[] | undefined => {
		if (!present(field)) return undefined;
		const value = slice[field];
		if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
			throw new Error(`${at(field)} must be a list of strings`);
		}
		return value as string[];
	};

	const issuer = requiredString("issuer");
	const clientId = requiredString("clientId");
	const callbackURL = requiredString("callbackURL");
	const clientSecret = optionalString("clientSecret");

	let privateKey: string | OidcPrivateKey | undefined;
	if (present("privateKey")) {
		const raw = slice.privateKey;
		if (typeof raw === "string" && raw.length > 0) {
			privateKey = raw;
		} else if (isObject(raw) && typeof raw.pem === "string" && raw.pem.length > 0) {
			for (const key of ["kid", "alg"]) {
				if (raw[key] !== undefined && raw[key] !== null && typeof raw[key] !== "string") {
					throw new Error(`${at(`privateKey.${key}`)} must be a string when present`);
				}
			}
			privateKey = {
				pem: raw.pem,
				...(typeof raw.kid === "string" ? { kid: raw.kid } : {}),
				...(typeof raw.alg === "string" ? { alg: raw.alg } : {}),
			};
		} else {
			throw new Error(`${at("privateKey")} must be a PEM string or { pem, kid?, alg? }`);
		}
	}
	if ((clientSecret === undefined) === (privateKey === undefined)) {
		throw new Error(
			`federations.${name} must set exactly one of clientSecret (client_secret_basic) or privateKey (private_key_jwt)`,
		);
	}

	let endpoints: OidcEndpointOverrides | undefined;
	if (present("endpoints")) {
		const raw = slice.endpoints;
		if (!isObject(raw)) throw new Error(`${at("endpoints")} must be an object of endpoint URLs`);
		const out: Record<string, string> = {};
		for (const key of Object.keys(raw)) {
			if (!(ENDPOINT_KEYS as readonly string[]).includes(key)) {
				throw new Error(
					`${at("endpoints")} has an unknown key "${key}" (expected ${ENDPOINT_KEYS.join(", ")})`,
				);
			}
			const value = raw[key];
			if (value === undefined || value === null) continue;
			if (typeof value !== "string") throw new Error(`${at(`endpoints.${key}`)} must be a string`);
			out[key] = value;
		}
		endpoints = out;
	}

	const scopes = optionalStringList("scopes");
	const discovery = optionalBoolean("discovery");
	const idTokenSignedResponseAlg = optionalString("idTokenSignedResponseAlg");
	const userInfo = optionalBoolean("userInfo");
	const clockToleranceSeconds = optionalNumber("clockToleranceSeconds");
	const redirectAllowlist = optionalStringList("redirectAllowlist");
	const sessionDomain = optionalString("sessionDomain");
	const authCallbackUrl = optionalString("authCallbackUrl");
	const clientUrl = optionalString("clientUrl");

	return {
		issuer,
		clientId,
		callbackURL,
		...(clientSecret !== undefined ? { clientSecret } : {}),
		...(privateKey !== undefined ? { privateKey } : {}),
		...(scopes !== undefined ? { scopes } : {}),
		...(discovery !== undefined ? { discovery } : {}),
		...(endpoints !== undefined ? { endpoints } : {}),
		...(idTokenSignedResponseAlg !== undefined ? { idTokenSignedResponseAlg } : {}),
		...(userInfo !== undefined ? { userInfo } : {}),
		...(clockToleranceSeconds !== undefined ? { clockToleranceSeconds } : {}),
		...(redirectAllowlist !== undefined ? { redirectAllowlist } : {}),
		...(sessionDomain !== undefined ? { sessionDomain } : {}),
		...(authCallbackUrl !== undefined ? { authCallbackUrl } : {}),
		...(clientUrl !== undefined ? { clientUrl } : {}),
	};
}

/**
 * The `oidcFederationConfigs` slot from the `federations` config section:
 * every enabled section whose `type` is `oidc`, flat or nested (the shapes
 * `extractFederationSection` accepts), checked field by field so a typo is a
 * boot refusal naming `federations.<name>.<field>` rather than a provider
 * running with one fewer setting than the operator wrote down. The map has
 * no prototype, and every name is checked before it becomes a key: a
 * section the config parser named `__proto__` is refused by name rather
 * than assigned through the prototype setter.
 */
export function readOidcFederationConfigs(
	federations: Record<string, unknown> | undefined,
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
