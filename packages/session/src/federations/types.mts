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

export type FederationResult<T> =
	| { ok: true; value: T }
	| { ok: false; status: number; error: string; errorDescription: string };

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
	 * Build the authorization URL for RFC 6749 §4.1 + RFC 7636 code flow.
	 *
	 * `codeVerifier` MUST be a cryptographically strong URL-safe random string; the route
	 * layer generates and stores it in the session before calling. Adapters compute
	 * `code_challenge` via the shared `pkce` helper (`codeChallenge(codeVerifier)`); do
	 * not accept a pre-computed challenge to avoid mismatches between transform methods.
	 */
	buildAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
	}): URL;

	/**
	 * Exchange an authorization `code` for a normalized `FederationProfile`.
	 *
	 * Adapters post to the IdP's token endpoint, optionally call the userinfo endpoint,
	 * and return a `FederationProfile`. They MUST include `issuer` and `sub`; all other
	 * standard fields are optional.
	 */
	exchangeCode(params: {
		readonly code: string;
		readonly codeVerifier: string;
		readonly redirectUri: string;
	}): Promise<FederationProfile>;

	/** URL-pattern validation for a consumer-supplied `redirect_to` (retained from old interface). */
	validateRedirect(url: string): FederationResult<void>;
	/** Resolve the post-callback redirect URL from the session's `redirectTo`. */
	resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
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
