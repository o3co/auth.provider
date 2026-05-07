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

import { defineModule } from "@o3co/auth-provider-core";
import {
	codeChallenge,
	createFederationRedirectPolicy,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationProfile,
	type FederationProvider,
	type MappedClaims,
	type RefreshedTokens,
	type SupportsClaimMapping,
	type SupportsLogout,
	type SupportsRefresh,
} from "@o3co/auth-provider-session";
import * as oidc from "openid-client";

// ComponentMap slot declaration-merge: exposes googleFederationConfig as a typed
// DI slot. Consumers supply this via a small bootstrap module that reads from
// app config (per A5 §10.1 const-Module pattern).
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly googleFederationConfig?: GoogleProviderConfig;
	}
}

const GOOGLE_ISSUER = "https://accounts.google.com";
const SCOPES = ["openid", "profile", "email"] as const;
const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

export interface GoogleProviderConfig {
	clientId: string;
	clientSecret: string;
	callbackURL: string;
	/** Cookie / session domain used to validate redirect URLs (e.g. ".example.com"). Optional. */
	sessionDomain?: string;
	/** URL of the auth-callback page (used to build the post-login redirect). Optional. */
	authCallbackUrl?: string;
	/** Fallback URL for the client app (used when no redirectTo is present). Optional. */
	clientUrl?: string;
	/** Override Google's end-session endpoint. When omitted, the provider redirects directly
	 *  to postLogoutRedirectUri (or accounts.google.com/Logout as fallback). */
	endSessionEndpoint?: string;
	/** Override Google's JWKS URI. Default: `https://www.googleapis.com/oauth2/v3/certs`.
	 *  Test injection only — production deployments rely on the default. */
	jwksUri?: string;
	/** Clock skew tolerance in seconds for id_token iat/exp validation, applied via openid-client's
	 *  `[clockSkew]` Symbol on the Configuration. Default: openid-client's built-in tolerance.
	 *  Optional and bounded — RFC 8725 §3.10 cautions against unbounded skew. */
	clockSkewSeconds?: number;
}

export type GoogleProvider = FederationProvider &
	SupportsRefresh &
	SupportsLogout &
	SupportsClaimMapping;

export function createGoogleProvider(config: GoogleProviderConfig): GoogleProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(`Google federation "google" requires clientId, clientSecret, and callbackURL`);
	}

	// ServerMetadata constructed locally — no discovery call. Google's endpoints are stable.
	// Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
	//
	// PB-4: `jwks_uri` is required for id_token RS256 signature verification; without it
	// openid-client treats id_tokens as opaque (silent verification skip). The
	// `id_token_signing_alg_values_supported` list pins `RS256` so the library refuses to
	// honour `none` / `HS256` confusion attacks should the published JWKS be coerced.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: GOOGLE_ISSUER,
		authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		token_endpoint: "https://oauth2.googleapis.com/token",
		userinfo_endpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
		jwks_uri: config.jwksUri ?? GOOGLE_JWKS_URI,
		id_token_signing_alg_values_supported: ["RS256"],
	};

	const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);

	// Optional clock-skew tolerance (RFC 8725 §3.10). openid-client v6 reads the value via
	// the `[oidc.clockSkew]` Symbol on the Configuration object. Bounded by the operator —
	// no implicit fallback so unset means "library default" rather than a silent permissive
	// skew.
	if (typeof config.clockSkewSeconds === "number" && Number.isFinite(config.clockSkewSeconds)) {
		(oidcConfig as unknown as Record<symbol, number>)[oidc.clockSkew] = config.clockSkewSeconds;
	}

	return {
		name: "google",
		scope: SCOPES,

		buildAuthorizationUrl(params: {
			readonly redirectUri: string;
			readonly state: string;
			readonly codeVerifier: string;
			readonly nonce?: string;
		}): URL {
			// PB-4: when the route layer supplies a `nonce`, forward it as the upstream `nonce`
			// authorization param so Google embeds it in the id_token. The matching
			// `expectedNonce` check in `exchangeCode` then binds the id_token to this session.
			return oidc.buildAuthorizationUrl(oidcConfig, {
				redirect_uri: params.redirectUri,
				scope: SCOPES.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
				access_type: "offline",
				...(params.nonce ? { nonce: params.nonce } : {}),
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
			readonly nonce?: string;
		}): Promise<FederationProfile> {
			// openid-client's authorizationCodeGrant expects the full callback URL.
			// We synthesize it from redirectUri + code since the route receives them separately.
			const callbackUrl = new URL(params.redirectUri);
			callbackUrl.searchParams.set("code", params.code);

			// PB-4: passing `expectedNonce` activates openid-client's nonce check (OIDC §3.1.3.7)
			// and *also* asserts an id_token is present in the response. When `params.nonce` is
			// undefined the option is omitted entirely — callers without nonce wiring keep the
			// pre-PB-4 behavior, but the route layer now always supplies it for OIDC providers.
			const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				expectedState: oidc.skipStateCheck,
				...(params.nonce !== undefined ? { expectedNonce: params.nonce } : {}),
			});

			// PB-5: bind UserInfo response sub against the verified id_token sub (OIDC §5.3.2).
			// When the id_token carries no sub (degenerate or non-OIDC token sets) we fall back
			// to skipSubjectCheck — the OAuth-only path was never bound here, and we do not want
			// to start failing closed for tokens that legitimately have no id-level identity.
			const idTokenClaims = tokens.claims();
			const idTokenSub = typeof idTokenClaims?.sub === "string" ? idTokenClaims.sub : undefined;
			const userInfo = await oidc.fetchUserInfo(
				oidcConfig,
				tokens.access_token,
				idTokenSub ?? oidc.skipSubjectCheck,
			);

			const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;

			// Extension claims: anything beyond first-class fields lands on the profile
			// via the index signature — no `raw` wrapper needed.
			const profile: FederationProfile = {
				issuer: GOOGLE_ISSUER,
				sub: typeof userInfo.sub === "string" ? userInfo.sub : "",
				email: typeof userInfo.email === "string" ? userInfo.email : undefined,
				emailVerified:
					typeof userInfo.email_verified === "boolean" ? userInfo.email_verified : undefined,
				name: typeof userInfo.name === "string" ? userInfo.name : undefined,
				picture: typeof userInfo.picture === "string" ? userInfo.picture : undefined,
				accessToken: tokens.access_token,
				refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
				idToken: typeof tokens.id_token === "string" ? tokens.id_token : undefined,
				expiresAt: new Date(Date.now() + expiresIn * 1000),
			};

			// Carry through known extension claims (e.g. Google hd).
			if (typeof userInfo.hd === "string") {
				(profile as Record<string, unknown>).hd = userInfo.hd;
			}

			return profile;
		},

		async refreshToken(refreshTokenValue: string): Promise<RefreshedTokens> {
			const tokens = await oidc.refreshTokenGrant(oidcConfig, refreshTokenValue);
			const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;
			return {
				accessToken: tokens.access_token,
				refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
				idToken: typeof tokens.id_token === "string" ? tokens.id_token : undefined,
				expiresAt: new Date(Date.now() + expiresIn * 1000),
				// sub / issuer intentionally absent — callers reuse stored identity.
			};
		},

		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			// Google does not publish an OIDC end_session_endpoint in its discovery document.
			// Operators MUST pass endSessionEndpoint explicitly for upstream logout.
			// Absent that, redirect directly to postLogoutRedirectUri (or accounts.google.com/Logout).
			if (config.endSessionEndpoint) {
				let url: URL;
				try {
					url = new URL(config.endSessionEndpoint);
				} catch {
					throw new Error(
						`Google federation "google" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
					);
				}
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			const base = req.postLogoutRedirectUri ?? `${GOOGLE_ISSUER}/Logout`;
			let url: URL;
			try {
				url = new URL(base);
			} catch {
				throw new Error(
					`Google federation "google" received an invalid postLogoutRedirectUri: ${base}`,
				);
			}
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},

		mapClaims(profile: FederationProfile): MappedClaims {
			const claims: Record<string, unknown> = {};
			if (typeof profile.email === "string") claims.email = profile.email;
			if (typeof profile.emailVerified === "boolean") claims.emailVerified = profile.emailVerified;
			if (typeof profile.name === "string") claims.name = profile.name;
			if (typeof profile.picture === "string") claims.picture = profile.picture;
			// Pass through extension claims (e.g. hd for Google Workspace domain restriction).
			if (typeof profile.hd === "string") claims.hd = profile.hd;
			return claims as MappedClaims;
		},
	};
}

/**
 * Const Module for the Google federation integration.
 *
 * Contributes both `federations.google` (FederationProvider — upstream OIDC
 * protocol) and `federationRedirectPolicies.google` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `googleFederationConfig` ComponentMap slot
 * (per A5 §10.1 const-Module pattern). v0.5.0 is single-tenant: the federation
 * is registered under name "google". Multi-tenant support deferred post-publish.
 *
 * Per A5 §10.1.
 */
export const googleFederationModule = defineModule({
	name: "federation:google",
	requires: ["googleFederationConfig"] as const,
	contributes: {
		federations: {
			// v0.5.0 is single-tenant: provider.name is fixed at "google".
			// Multi-tenant support deferred to post-publish; consumers needing
			// multiple Google apps will get an additive Config shape.
			google: (deps) => createGoogleProvider(deps.googleFederationConfig),
		},
		federationRedirectPolicies: {
			google: (deps) => createFederationRedirectPolicy(deps.googleFederationConfig),
		},
	},
});
