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

import type { FederationResponseMode } from "./response-mode.mjs";

export type FederationResult<T> =
	| { readonly ok: true; readonly value: T }
	| {
			readonly ok: false;
			readonly status: number;
			readonly error: string;
			readonly errorDescription: string;
	  };

/**
 * Snapshot of a successful federation callback: identity + OIDC-standard claims + OAuth 2 tokens.
 *
 * The `[key: string]: unknown` index signature is an extension slot for provider-specific claims
 * (Google `hd`, Microsoft `tid`, etc). Promote a claim to first-class only when it becomes
 * widely useful across providers (see Migration Guide in the spec).
 *
 * Fields are ordered to match the RFC 6749 §5.1 + OIDC Core §5.1 claim sources.
 */
export interface FederationProfile {
	/** IdP issuer URL (OIDC discovery `issuer`) or provider name for non-OIDC providers. */
	readonly issuer: string;
	/** OIDC `sub` claim — stable identifier for the federated user at this IdP. */
	readonly sub: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	/** OAuth 2 access token for subsequent IdP API calls. */
	readonly accessToken?: string;
	/** Refresh token; absent if the IdP did not issue one. */
	readonly refreshToken?: string;
	/** OIDC id_token JWT, if issued. */
	readonly idToken?: string;
	/**
	 * Absolute expiry time of `accessToken`, derived from `expires_in` by the adapter.
	 *
	 * `null` means the provider did not issue a finite expiry (e.g. GitHub OAuth Apps
	 * classic tokens). Consumers MUST treat `null` as "do not attempt refresh; reuse
	 * until the provider explicitly invalidates". Required (no `undefined`) so adapters
	 * are forced to make an explicit decision per provider rather than the route layer
	 * inventing a fallback expiry.
	 */
	readonly expiresAt: Date | null;
	/** Provider-specific extension claims (e.g. Google `hd`, Microsoft `tid`). */
	readonly [key: string]: unknown;
}

/**
 * Pure-function interface for an upstream OAuth 2 / OIDC identity provider.
 *
 * Implementations MUST NOT expose vendor library types (passport, arctic, openid-client, etc)
 * through this interface or through types exported alongside it. Adapters should keep vendor
 * concerns below a ≤50-line facade (target).
 *
 * State (CSRF `state`, PKCE `codeVerifier`) is managed by the session route layer and passed
 * into both calls; providers never allocate state themselves.
 */
export interface FederationProvider {
	readonly name: string;
	readonly scope: readonly string[];

	/**
	 * How this IdP delivers the authorization response — `"query"` (the
	 * default, and what every federation written before Sign in with Apple
	 * assumed) or `"form_post"`.
	 *
	 * Declaring `"form_post"` changes three things in the route layer, and
	 * nothing in the adapter:
	 *
	 * 1. the start route appends `response_mode=form_post` to the URL this
	 *    provider's `buildAuthorizationUrl` returned, so the parameter is
	 *    written once for every federation instead of in each adapter;
	 * 2. `POST /oauth/federation/<name>/callback` starts accepting an
	 *    `application/x-www-form-urlencoded` body, with the same state / PKCE
	 *    / nonce binding as the GET callback (a provider that does not declare
	 *    the mode answers 405 there, so no existing federation gains a POST
	 *    surface);
	 * 3. the session cookie carrying this federation's ephemeral state is
	 *    marked `SameSite=None; Secure` for that one session, because the
	 *    callback arrives as a cross-site POST — see `applyCrossSiteStateCookie`.
	 *
	 * Optional, and an unrecognised value is read as the default: absence must
	 * mean "query" for every provider that predates this field.
	 */
	readonly responseMode?: FederationResponseMode;

	/**
	 * Build the authorization URL for RFC 6749 §4.1 + RFC 7636 code flow.
	 *
	 * `codeVerifier` MUST be a cryptographically strong URL-safe random string; the route
	 * layer generates and stores it in the session before calling. Adapters compute
	 * `code_challenge` via the shared `pkce` helper (`codeChallenge(codeVerifier)`); do
	 * not accept a pre-computed challenge to avoid mismatches between transform methods.
	 *
	 * `nonce` is optional — OIDC providers MUST forward it as the upstream `nonce`
	 * authorization param so that the matching `expectedNonce` check in `exchangeCode`
	 * binds the returned id_token to this session (OIDC Core §3.1.3.7). OAuth-only
	 * providers (e.g. GitHub OAuth Apps) ignore it.
	 */
	buildAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
		readonly nonce?: string;
	}): URL;

	/**
	 * Exchange an authorization `code` for a normalized `FederationProfile`.
	 *
	 * Adapters post to the IdP's token endpoint, optionally call the userinfo endpoint,
	 * and return a `FederationProfile`. They MUST include `issuer` and `sub`; all other
	 * standard fields are optional.
	 *
	 * `nonce` is optional — OIDC providers MUST pass it as `expectedNonce` to the
	 * upstream library so that the id_token nonce claim is verified against the
	 * session-stored value (OIDC Core §3.1.3.7). OAuth-only providers ignore it.
	 */
	exchangeCode(params: {
		readonly code: string;
		readonly codeVerifier: string;
		readonly redirectUri: string;
		readonly nonce?: string;
		/**
		 * The rest of the callback's parameters — query string for a `"query"`
		 * federation, form body for a `"form_post"` one — with only the string
		 * values kept.
		 *
		 * **`code` and `state` are excluded.** Both are the framework's to bind,
		 * and both are already accounted for: `code` arrives in its own field
		 * above, and `state` is the value the route compared against the session
		 * before calling. Leaving them in would put each in two places, one of
		 * which the route validated and one of which it did not — so an adapter
		 * cannot read a credential from the wrong one, because the wrong one is
		 * not there.
		 *
		 * Present so an IdP that returns identity data *beside* the token
		 * response can be adapted without a second callback contract: Apple
		 * sends the end user's name exactly once, in a `user` JSON field on the
		 * first authorization, and never in the id_token.
		 *
		 * **These values are relayed through the user agent and are not signed.**
		 * The `state` check binds them to this session, which is all it binds:
		 * an adapter must treat anything read here as self-asserted, and the
		 * route layer keeps whatever `mapClaims` makes of it under
		 * `claims.federated[<provider>]` subject to the ordinary promotion
		 * rules (see `claim-precedence.mts`) — never as an authorization input.
		 */
		readonly callbackParams?: Readonly<Record<string, string>>;
	}): Promise<FederationProfile>;
}

/**
 * Arguments for an OIDC RP-Initiated Logout (end-session) request. Unchanged from v0.3.x.
 */
export interface EndSessionRequest {
	idTokenHint?: string;
	postLogoutRedirectUri?: string;
	state?: string;
}

export interface EndSessionResult {
	url: URL;
	method: "GET";
}

export interface SupportsLogout {
	endSession(req: EndSessionRequest): Promise<EndSessionResult>;
}

export function supportsLogout(
	provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsLogout {
	if (provider == null) return false;
	return typeof (provider as { endSession?: unknown }).endSession === "function";
}

export interface MappedClaims {
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: ReadonlyArray<string>;
	readonly [key: string]: unknown;
}

export interface SupportsClaimMapping {
	mapClaims(profile: FederationProfile): MappedClaims;
}

export function supportsClaimMapping(
	p: FederationProvider | undefined | null,
): p is FederationProvider & SupportsClaimMapping {
	if (p == null) return false;
	return typeof (p as { mapClaims?: unknown }).mapClaims === "function";
}

/**
 * Partial token snapshot returned by `SupportsRefresh.refreshToken`.
 *
 * `issuer` and `sub` are optional because callers reuse the stored identity from the
 * original federation profile — the refresh grant does not re-assert identity. All other
 * token fields follow the same semantics as `FederationProfile`.
 */
export type RefreshedTokens = Omit<FederationProfile, "issuer" | "sub"> & {
	readonly issuer?: string;
	readonly sub?: string;
};

export interface SupportsRefresh {
	/** Refresh an upstream IdP access token using its refresh token. Returns a partial token snapshot. */
	refreshToken(refreshToken: string): Promise<RefreshedTokens>;
}

export function supportsRefresh(
	p: FederationProvider | undefined | null,
): p is FederationProvider & SupportsRefresh {
	if (p == null) return false;
	return typeof (p as { refreshToken?: unknown }).refreshToken === "function";
}
