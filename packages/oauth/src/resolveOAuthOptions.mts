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

import { type AcrTable, type Logger, readAcrTable } from "@o3co/auth-provider-core";
import { type ResolvedPkceOptions, resolvePkceOptions } from "./grants/pkce.mjs";

/**
 * The `oauth.*` knobs the OAuth routers and grants consume, resolved once at
 * composition time. Plain data — consumers never re-read `config` per request.
 */
export interface ResolvedOAuthOptions {
	/**
	 * Raw `oauth.jwt.issuer` value, deliberately NOT validated or narrowed
	 * here: `checkCanonicalIssuer` stays the single validator, and the
	 * router surfaces its per-rejection operator message at construction time.
	 */
	readonly issuer: unknown;
	/**
	 * Defaults to `false`, but is resolved WITHOUT the `?? false` fallback:
	 * sub-routers (userinfo, logout, federation-token) receive the raw
	 * optional and apply their own defaulting.
	 */
	readonly legacyTypAccept: boolean | undefined;
	/**
	 * When acting as an OIDC OP, `/authorize` rejects requests
	 * that omit `openid` unless operators explicitly chose dual OAuth/OIDC mode.
	 */
	readonly oidcMode: "oidc-required" | "dual";
	/** Gate token issuance on Store-published email verification. */
	readonly requireEmailVerified: boolean;
	/**
	 * The single PKCE policy for the authorization-code flow. `/authorize`
	 * reads it from here; `/token` (the authorization grant) resolves the same
	 * object from the same config, so the two endpoints cannot disagree about
	 * whether a code they mint is redeemable. See `grants/pkce.mts`.
	 */
	readonly pkce: ResolvedPkceOptions;
	/**
	 * Ceiling for the OIDC `nonce` query parameter, operator-
	 * tunable via `oauth.nonce.maxLength` (default in core HOCON, env-var
	 * `OAUTH_NONCE_MAX_LENGTH`).
	 */
	readonly nonceMaxLength: number;
	/** RFC 8707: opt-in gate for Resource Indicator enforcement. */
	readonly resourceIndicatorEnabled: boolean;
	/**
	 * `oauth.authorize.acrValues` — each acr and the amr values a session
	 * must carry, or the alternatives any one of which it must (ADR
	 * 2026-09-25-multi-factor-authentication), as core's `readAcrTable` reads
	 * it; empty when unset.
	 * This is the configured table: the router narrows it to what the
	 * composition can satisfy (`vouchableAcrValues`) before `/authorize` reads
	 * it.
	 */
	readonly acrValues: AcrTable;
	/**
	 * Client ID Metadata Documents, resolved to plain lists and numbers
	 * whatever shape the config carried them in — an environment variable
	 * hands a list over as one comma-separated string, and a hand-built
	 * config may do the same.
	 */
	readonly clientIdMetadataDocuments: {
		readonly enabled: boolean;
		readonly allowedScopes: readonly string[];
		readonly allowedAudiences: readonly string[];
		readonly allowedHosts: readonly string[];
		readonly deniedHosts: readonly string[];
		readonly maxBytes: number | undefined;
		readonly timeoutMs: number | undefined;
		readonly cacheMaxAgeMs: number | undefined;
		readonly maxCacheEntries: number | undefined;
		readonly staleIfErrorMs: number | undefined;
		readonly negativeCacheMs: number | undefined;
		readonly maxConcurrentFetches: number | undefined;
	};
	/**
	 * When true, a client that declares no `allowedGrantTypes` is denied
	 * every grant instead of being unrestricted. Resolved here so both
	 * enforcement points read one value decided at composition.
	 */
	readonly requireGrantTypeAllowlist: boolean;
}

/**
 * Shape-only view of the `oauth` config block. This is the ONE place the
 * defensive cast lives: every field is read through optional chaining so
 * hand-built configs that never passed the zod schema (`AppConfigSchema`)
 * — test fixtures, embedders composing their own `AppConfig` — resolve to
 * safe defaults.
 */
type OAuthConfigShape = {
	jwt?: { issuer?: unknown; legacyTypAccept?: boolean };
	oidcMode?: "oidc-required" | "dual";
	requireEmailVerified?: boolean;
	requireGrantTypeAllowlist?: boolean;
	// `authorize` is deliberately absent, so a stale `allowUnmarkedClients`
	// stays inert; `acrValues` is read through its own cast below.
	grants?: Record<string, Record<string, unknown> | undefined>;
	nonce?: { maxLength?: number };
	resourceIndicator?: { enabled?: boolean };
	clientIdMetadataDocuments?: {
		enabled?: unknown;
		allowedScopes?: unknown;
		allowedAudiences?: unknown;
		allowedHosts?: unknown;
		deniedHosts?: unknown;
		maxBytes?: unknown;
		timeoutMs?: unknown;
		cacheMaxAgeMs?: unknown;
		maxCacheEntries?: unknown;
		staleIfErrorMs?: unknown;
		negativeCacheMs?: unknown;
		maxConcurrentFetches?: unknown;
	};
};

/**
 * A list from an array, a comma-separated string, or nothing.
 *
 * Trimmed and emptied the same way whichever shape it arrived in: a HOCON
 * array entry can carry surrounding space as surely as an environment
 * override can, and a host policy that silently keeps `" .trusted.example"`
 * refuses the URL the operator meant to allow.
 */
const listOf = (value: unknown): readonly string[] => {
	const parts = Array.isArray(value)
		? value.filter((v): v is string => typeof v === "string")
		: typeof value === "string"
			? value.split(",")
			: [];
	return parts.map((v) => v.trim()).filter((v) => v.length > 0);
};

const positiveIntOrUndefined = (value: unknown): number | undefined => {
	const n = typeof value === "string" ? Number(value) : value;
	return typeof n === "number" && Number.isInteger(n) && n >= 0 ? n : undefined;
};

/**
 * Resolves every `oauth.*` knob the OAuth routers and grants consume into one
 * plain typed options object, at composition time, tolerating a hand-built
 * config that bypassed the schema. Defaults:
 *
 * - boolean opt-ins (`requireEmailVerified`, `resourceIndicator.enabled`)
 *   enable only on literal `true`; an absent value reads `false`;
 * - `oidcMode` falls back to `"oidc-required"`;
 * - `nonce.maxLength` falls back to `256`;
 * - `legacyTypAccept` stays `undefined` when absent (consumers default it);
 * - `pkce` is fixed policy, not a knob: `resolvePkceOptions` returns
 *   required + S256-only whatever the config says, and warns about the keys
 *   that no longer do anything;
 * - `acrValues` is the configured table, or an empty one, read by core's
 *   `readAcrTable` — the one reading, which discovery shares. It has no
 *   prototype, because an `acr_values` an unauthenticated caller chooses is
 *   used as a key into it: on a plain object a request asking for
 *   `constructor` would read `Object`.
 *
 * The optional `logger` receives the `resolvePkceOptions` inert-config
 * warning, once at boot rather than once per `/authorize` request.
 */

export const resolveOAuthOptions = (config: unknown, logger?: Logger): ResolvedOAuthOptions => {
	const oauth = (config as { oauth?: OAuthConfigShape } | undefined)?.oauth;

	// Read the pkce block only to report what is now inert in it.
	// `oauth.grants` is `z.object({}).passthrough()` in the schema, so even a
	// schema-validated tree is untyped from here down.
	const authorizationConfig = oauth?.grants?.authorization_code;
	const pkceConfig = authorizationConfig?.pkce as Record<string, unknown> | undefined;

	return {
		issuer: oauth?.jwt?.issuer,
		legacyTypAccept: oauth?.jwt?.legacyTypAccept,
		oidcMode: oauth?.oidcMode ?? "oidc-required",
		requireEmailVerified: oauth?.requireEmailVerified === true,
		pkce: resolvePkceOptions(pkceConfig, logger),
		nonceMaxLength: oauth?.nonce?.maxLength ?? 256,
		resourceIndicatorEnabled: oauth?.resourceIndicator?.enabled === true,
		acrValues: readAcrTable(
			(oauth as { authorize?: { acrValues?: unknown } } | undefined)?.authorize?.acrValues,
		),
		clientIdMetadataDocuments: {
			enabled: oauth?.clientIdMetadataDocuments?.enabled === true,
			allowedScopes: listOf(oauth?.clientIdMetadataDocuments?.allowedScopes),
			allowedAudiences: listOf(oauth?.clientIdMetadataDocuments?.allowedAudiences),
			allowedHosts: listOf(oauth?.clientIdMetadataDocuments?.allowedHosts),
			deniedHosts: listOf(oauth?.clientIdMetadataDocuments?.deniedHosts),
			maxBytes: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.maxBytes),
			timeoutMs: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.timeoutMs),
			cacheMaxAgeMs: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.cacheMaxAgeMs),
			maxCacheEntries: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.maxCacheEntries),
			staleIfErrorMs: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.staleIfErrorMs),
			negativeCacheMs: positiveIntOrUndefined(oauth?.clientIdMetadataDocuments?.negativeCacheMs),
			maxConcurrentFetches: positiveIntOrUndefined(
				oauth?.clientIdMetadataDocuments?.maxConcurrentFetches,
			),
		},
		requireGrantTypeAllowlist: oauth?.requireGrantTypeAllowlist === true,
	};
};
