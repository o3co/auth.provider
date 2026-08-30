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

import type { Logger } from "@o3co/auth-provider-core";
import { type ResolvedPkceOptions, resolvePkceOptions } from "./grants/pkce.mjs";

/**
 * The `oauth.*` knobs the OAuth routers and grants consume, resolved once at
 * composition time. Plain data — consumers never re-read `config` per request.
 */
export interface ResolvedOAuthOptions {
	/**
	 * Raw `oauth.jwt.issuer` value, deliberately NOT validated or narrowed
	 * here: `checkCanonicalIssuer` (#266) stays the single validator, and the
	 * router surfaces its per-rejection operator message at construction time.
	 */
	readonly issuer: unknown;
	/**
	 * SF-1 / Phase G / S2: legacyTypAccept default is `false` (v0.5.x was
	 * `true`). Resolved WITHOUT the `?? false` fallback: sub-routers (userinfo,
	 * logout, federation-token) receive the raw optional and apply their own
	 * defaulting, exactly as they did when routes.mts read the field inline.
	 */
	readonly legacyTypAccept: boolean | undefined;
	/**
	 * IH-6 (v0.5.3): when acting as an OIDC OP, `/authorize` rejects requests
	 * that omit `openid` unless operators explicitly chose dual OAuth/OIDC mode.
	 */
	readonly oidcMode: "oidc-required" | "dual";
	/** #297: gate token issuance on Store-published email verification. */
	readonly requireEmailVerified: boolean;
	/**
	 * #273: the single PKCE policy for the authorization-code flow. `/authorize`
	 * reads it from here; `/token` (the authorization grant) resolves the same
	 * object from the same config, so the two endpoints cannot disagree about
	 * whether a code they mint is redeemable. See `grants/pkce.mts`.
	 */
	readonly pkce: ResolvedPkceOptions;
	/**
	 * IH-16 (v0.5.1): ceiling for the OIDC `nonce` query parameter, operator-
	 * tunable via `oauth.nonce.maxLength` (default in core HOCON, env-var
	 * `OAUTH_NONCE_MAX_LENGTH`).
	 */
	readonly nonceMaxLength: number;
	/** Wave 1 §5.3 (RFC 8707): opt-in gate for Resource Indicator enforcement. */
	readonly resourceIndicatorEnabled: boolean;
	/**
	 * #311: when true, a client that declares no `allowedGrantTypes` is denied
	 * every grant instead of being unrestricted. Resolved here so both
	 * enforcement points #268 added read one value decided at composition.
	 */
	readonly requireGrantTypeAllowlist: boolean;
}

/**
 * Shape-only view of the `oauth` config block. This is the ONE place the
 * defensive cast lives (#328): every field is read through optional chaining
 * so hand-built configs that never passed the zod schema (`AppConfigSchema`)
 * — test fixtures, embedders composing their own `AppConfig` — resolve to the
 * same safe defaults the inline casts in routes.mts used to produce.
 */
type OAuthConfigShape = {
	jwt?: { issuer?: unknown; legacyTypAccept?: boolean };
	oidcMode?: "oidc-required" | "dual";
	requireEmailVerified?: boolean;
	requireGrantTypeAllowlist?: boolean;
	// `authorize` is deliberately absent: its only key, `allowUnmarkedClients`,
	// was removed in #330 and a stale value must stay inert here too.
	grants?: Record<string, Record<string, unknown> | undefined>;
	nonce?: { maxLength?: number };
	resourceIndicator?: { enabled?: boolean };
};

/**
 * Resolves every `oauth.*` knob the OAuth routers and grants consume into one
 * plain typed options object, at composition time.
 *
 * Replaces the per-site `config as { oauth?: ... }` casts that had spread
 * through `routes.mts` and `grants/session.mts`: each new knob re-implemented
 * the "tolerate a hand-built config that bypassed the schema" defensive read,
 * at inconsistent altitude (router construction vs per request). Values pass
 * through untouched — no coercion, no validation — so a config that lies about
 * its types behaves exactly as it did against the inline casts. Defaults:
 *
 * - boolean opt-ins (`requireEmailVerified`, `resourceIndicator.enabled`)
 *   enable only on literal `true` — the safe reading of an absent value is
 *   `false` (enforce/off);
 * - `oidcMode` falls back to `"oidc-required"`;
 * - `nonce.maxLength` falls back to `256`;
 * - `legacyTypAccept` stays `undefined` when absent (consumers default it);
 * - `pkce` is fixed policy, not a knob (#273): `resolvePkceOptions` returns
 *   required + S256-only whatever the config says, and warns about the keys
 *   that no longer do anything.
 *
 * The optional `logger` receives the `resolvePkceOptions` inert-config
 * warning. Resolution runs once at composition, so an operator sees one
 * boot-time warning instead of one per `/authorize` request.
 */
export const resolveOAuthOptions = (config: unknown, logger?: Logger): ResolvedOAuthOptions => {
	const oauth = (config as { oauth?: OAuthConfigShape } | undefined)?.oauth;

	// #273: read the pkce block only to report what is now inert in it.
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
		requireGrantTypeAllowlist: oauth?.requireGrantTypeAllowlist === true,
	};
};
