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
	createDefaultFederationRedirectPolicy,
	type EndSessionRequest,
	type EndSessionResult,
	type FederationProfile,
	type FederationProvider,
	type FederationProviderFactory,
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

export interface GoogleProviderConfig {
	/** Strategy identifier — use a unique name per tenant for multi-tenant setups. */
	name: string;
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
}

export type GoogleProvider = FederationProvider &
	SupportsRefresh &
	SupportsLogout &
	SupportsClaimMapping;

function narrowGoogleConfig(config: Record<string, unknown>): GoogleProviderConfig {
	const name = typeof config.name === "string" ? config.name : undefined;
	const clientId = typeof config.clientId === "string" ? config.clientId : undefined;
	const clientSecret = typeof config.clientSecret === "string" ? config.clientSecret : undefined;
	const callbackURL = typeof config.callbackURL === "string" ? config.callbackURL : undefined;
	if (!name || !clientId || !clientSecret || !callbackURL) {
		throw new Error("Google federation requires name, clientId, clientSecret, and callbackURL");
	}
	return {
		name,
		clientId,
		clientSecret,
		callbackURL,
		sessionDomain: typeof config.sessionDomain === "string" ? config.sessionDomain : undefined,
		authCallbackUrl:
			typeof config.authCallbackUrl === "string" ? config.authCallbackUrl : undefined,
		clientUrl: typeof config.clientUrl === "string" ? config.clientUrl : undefined,
		endSessionEndpoint:
			typeof config.endSessionEndpoint === "string" ? config.endSessionEndpoint : undefined,
	};
}

export function registerGoogleFederation(factory: FederationProviderFactory): void {
	factory.register("google", async (config) => createGoogleProvider(narrowGoogleConfig(config)));
}

export function createGoogleProvider(config: GoogleProviderConfig): GoogleProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`Google federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}

	// ServerMetadata constructed locally — no discovery call. Google's endpoints are stable.
	// Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: GOOGLE_ISSUER,
		authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		token_endpoint: "https://oauth2.googleapis.com/token",
		userinfo_endpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
	};

	const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);

	return {
		name: config.name,
		scope: SCOPES,

		buildAuthorizationUrl(params: {
			readonly redirectUri: string;
			readonly state: string;
			readonly codeVerifier: string;
		}): URL {
			return oidc.buildAuthorizationUrl(oidcConfig, {
				redirect_uri: params.redirectUri,
				scope: SCOPES.join(" "),
				state: params.state,
				code_challenge: codeChallenge(params.codeVerifier),
				code_challenge_method: "S256",
				access_type: "offline",
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
		}): Promise<FederationProfile> {
			// openid-client's authorizationCodeGrant expects the full callback URL.
			// We synthesize it from redirectUri + code since the route receives them separately.
			const callbackUrl = new URL(params.redirectUri);
			callbackUrl.searchParams.set("code", params.code);

			const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
				pkceCodeVerifier: params.codeVerifier,
				expectedState: oidc.skipStateCheck,
			});

			const userInfo = await oidc.fetchUserInfo(
				oidcConfig,
				tokens.access_token,
				oidc.skipSubjectCheck,
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
						`Google federation "${config.name}" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
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
					`Google federation "${config.name}" received an invalid postLogoutRedirectUri: ${base}`,
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
 * (per A5 §10.1 const-Module pattern). Single-tenant baseline: one Google
 * federation under name "google". Multi-tenant consumers wrap with a factory
 * per A2-α §7.1.
 *
 * Per A5 §10.1.
 */
export const googleFederationModule = defineModule({
	name: "federation:google",
	requires: ["googleFederationConfig"] as const,
	contributes: {
		federations: {
			// const-module path is single-tenant: `provider.name` is forced to the
			// contribution key "google" regardless of `config.name`. The route
			// layer keys session state, callback URL lookup, and redirect-policy
			// resolution by `provider.name`; a divergent `config.name` would
			// cause silent runtime mismatch (provider.name="MyGoogle" registered
			// at federations.google → resolver lookup with key "MyGoogle" fails).
			// Multi-tenant consumers wrap with `(config) => Module` per
			// A5 §10.1 + A2-α §7.1 — that path supplies the contribution key
			// and `config.name` together.
			google: (deps) => ({ ...createGoogleProvider(deps.googleFederationConfig), name: "google" }),
		},
		federationRedirectPolicies: {
			google: (deps) => createDefaultFederationRedirectPolicy(deps.googleFederationConfig),
		},
	},
});
