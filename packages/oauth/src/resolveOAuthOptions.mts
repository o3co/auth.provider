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
import { resolvePkceSupportedMethods } from "./grants/pkce.mjs";

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
	 * #267: the migration escape hatch for the `/authorize` first-party
	 * invariant. `CoreConfigSchema` requires the key, so a deployment that
	 * boots through the schema has answered it deliberately.
	 */
	readonly allowUnmarkedClients: boolean;
	/** B-7/B-8: PKCE policy for the authorization-code flow. */
	readonly pkce: {
		readonly required: boolean;
		readonly defaultMethod: string;
		readonly supportedMethods: readonly string[];
	};
	/**
	 * IH-16 (v0.5.1): ceiling for the OIDC `nonce` query parameter, operator-
	 * tunable via `oauth.nonce.maxLength` (default in core HOCON, env-var
	 * `OAUTH_NONCE_MAX_LENGTH`).
	 */
	readonly nonceMaxLength: number;
	/** Wave 1 §5.3 (RFC 8707): opt-in gate for Resource Indicator enforcement. */
	readonly resourceIndicatorEnabled: boolean;
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
	authorize?: { allowUnmarkedClients?: boolean };
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
 * - boolean opt-ins (`requireEmailVerified`, `authorize.allowUnmarkedClients`,
 *   `resourceIndicator.enabled`, `pkce.required`) enable only on literal
 *   `true` — the safe reading of an absent value is `false` (enforce/off);
 * - `oidcMode` falls back to `"oidc-required"`;
 * - `nonce.maxLength` falls back to `256`;
 * - `legacyTypAccept` stays `undefined` when absent (consumers default it);
 * - `pkce.defaultMethod` falls back to `"plain"`, and `supportedMethods` goes
 *   through `resolvePkceSupportedMethods` (TS-4 — per-element validation, see
 *   grants/pkce.mts for the rationale).
 *
 * The optional `logger` receives `resolvePkceSupportedMethods` misconfig
 * warnings. Resolution runs once at composition, so an operator now sees one
 * boot-time warning instead of one per `/authorize` request.
 */
export const resolveOAuthOptions = (config: unknown, logger?: Logger): ResolvedOAuthOptions => {
	const oauth = (config as { oauth?: OAuthConfigShape } | undefined)?.oauth;

	// B-7/B-8: resolve PKCE config. `oauth.grants` is `z.object({}).passthrough()`
	// in the schema, so even a schema-validated tree is untyped from here down.
	const authorizationConfig = oauth?.grants?.authorization_code;
	const pkceConfig = authorizationConfig?.pkce as Record<string, unknown> | undefined;

	return {
		issuer: oauth?.jwt?.issuer,
		legacyTypAccept: oauth?.jwt?.legacyTypAccept,
		oidcMode: oauth?.oidcMode ?? "oidc-required",
		requireEmailVerified: oauth?.requireEmailVerified === true,
		allowUnmarkedClients: oauth?.authorize?.allowUnmarkedClients === true,
		pkce: {
			required: pkceConfig?.required === true,
			defaultMethod:
				typeof pkceConfig?.defaultMethod === "string" ? pkceConfig.defaultMethod : "plain",
			// TS-4 (v0.5.1): per-element validation via `resolvePkceSupportedMethods`.
			// See authorization.mts for the rationale — `Array.isArray + as string[]`
			// silently accepted non-string operator-typed values. Forward the logger
			// so the helper's misconfig warnings reach the operator.
			supportedMethods: resolvePkceSupportedMethods(pkceConfig, logger),
		},
		nonceMaxLength: oauth?.nonce?.maxLength ?? 256,
		resourceIndicatorEnabled: oauth?.resourceIndicator?.enabled === true,
	};
};
