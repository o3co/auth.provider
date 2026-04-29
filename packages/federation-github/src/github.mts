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
	type SupportsClaimMapping,
	type SupportsLogout,
} from "@o3co/auth-provider-session";
import * as oidc from "openid-client";

// ComponentMap slot declaration-merge: exposes githubFederationConfig as a typed
// DI slot. Consumers supply this via a small bootstrap module that reads from
// app config (per A5 §10.2 const-Module pattern).
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly githubFederationConfig?: GithubProviderConfig;
	}
}

const GITHUB_ISSUER = "https://github.com";
const SCOPES = ["read:user", "user:email"] as const;
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";

export interface GithubProviderConfig {
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
	/** Override GitHub's end-session endpoint. When omitted, the provider redirects directly
	 *  to postLogoutRedirectUri. */
	endSessionEndpoint?: string;
}

export type GithubProvider = FederationProvider & SupportsLogout & SupportsClaimMapping;

function narrowGithubConfig(config: Record<string, unknown>): GithubProviderConfig {
	const name = typeof config.name === "string" ? config.name : undefined;
	const clientId = typeof config.clientId === "string" ? config.clientId : undefined;
	const clientSecret = typeof config.clientSecret === "string" ? config.clientSecret : undefined;
	const callbackURL = typeof config.callbackURL === "string" ? config.callbackURL : undefined;
	if (!name || !clientId || !clientSecret || !callbackURL) {
		throw new Error("GitHub federation requires name, clientId, clientSecret, and callbackURL");
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

export function registerGithubFederation(factory: FederationProviderFactory): void {
	factory.register("github", async (config) => createGithubProvider(narrowGithubConfig(config)));
}

export function createGithubProvider(config: GithubProviderConfig): GithubProvider {
	if (!config.clientId || !config.clientSecret || !config.callbackURL) {
		throw new Error(
			`GitHub federation "${config.name}" requires clientId, clientSecret, and callbackURL`,
		);
	}

	// GitHub does not expose an OIDC discovery document, so we construct ServerMetadata manually.
	// Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
	const serverMetadata: oidc.ServerMetadata = {
		issuer: GITHUB_ISSUER,
		authorization_endpoint: "https://github.com/login/oauth/authorize",
		token_endpoint: "https://github.com/login/oauth/access_token",
		userinfo_endpoint: "https://api.github.com/user",
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
			});
		},

		async exchangeCode(params: {
			readonly code: string;
			readonly codeVerifier: string;
			readonly redirectUri: string;
		}): Promise<FederationProfile> {
			// Synthesize the callback URL from redirectUri + code.
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

			// GitHub's /user endpoint returns `id: number`, not the OIDC `sub` field.
			// openid-client passes the raw JSON through without remapping id → sub.
			// Coerce to string so every profile has a stable, non-empty sub.
			const ghId = (userInfo as { id?: unknown }).id;
			const sub =
				typeof userInfo.sub === "string" && userInfo.sub !== ""
					? userInfo.sub
					: typeof ghId === "number"
						? String(ghId)
						: typeof ghId === "string" && ghId !== ""
							? ghId
							: "";
			if (!sub) {
				throw new Error(`GitHub federation "${config.name}" received userinfo without id/sub`);
			}

			// Fetch primary+verified email from /user/emails.
			// GitHub's /user endpoint often omits email for users who keep it private.
			// Fallback order:
			//   1. primary + verified email
			//   2. first verified email (when primary is unverified)
			//   3. undefined (no verified email at all)
			let email: string | undefined;
			let emailVerified: boolean | undefined;
			try {
				const emailsRes = await oidc.fetchProtectedResource(
					oidcConfig,
					tokens.access_token,
					new URL(GITHUB_EMAILS_URL),
					"GET",
				);
				const rows = (await emailsRes.json()) as Array<{
					email?: unknown;
					primary?: unknown;
					verified?: unknown;
				}>;
				if (Array.isArray(rows)) {
					const verified = rows.filter((r) => r.verified === true && typeof r.email === "string");
					const primary = verified.find((r) => r.primary === true);
					const chosen = primary ?? verified[0];
					if (chosen && typeof chosen.email === "string") {
						email = chosen.email;
						emailVerified = true;
					}
				}
			} catch {
				// Transient /user/emails failure treated as "no email available" — never kills login.
			}

			const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : undefined;

			// GitHub's /user returns `avatar_url` (not the OIDC `picture` field).
			const ghAvatarUrl = (userInfo as { avatar_url?: unknown }).avatar_url;
			return {
				issuer: GITHUB_ISSUER,
				sub,
				email,
				emailVerified,
				name: typeof userInfo.name === "string" ? userInfo.name : undefined,
				picture: typeof ghAvatarUrl === "string" ? ghAvatarUrl : undefined,
				accessToken: tokens.access_token,
				// GitHub OAuth Apps do not issue refresh tokens.
				refreshToken: undefined,
				// GitHub OAuth Apps classic tokens have no finite expiry; the new-style
				// user-to-server tokens (`expires_in`-bearing) do. `null` signals "reuse,
				// do not attempt refresh" — see FederationProfile.expiresAt contract.
				expiresAt: expiresIn !== undefined ? new Date(Date.now() + expiresIn * 1000) : null,
			};
		},

		// GitHub has no RP-Initiated Logout endpoint by default.
		// Precedence: (1) configured endSessionEndpoint wins; (2) postLogoutRedirectUri redirect;
		// (3) fallback to https://github.com/logout (preserves pre-Task-3 behaviour, supports GitHub Enterprise).
		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			if (config.endSessionEndpoint) {
				let url: URL;
				try {
					url = new URL(config.endSessionEndpoint);
				} catch {
					throw new Error(
						`GitHub federation "${config.name}" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`,
					);
				}
				if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
				if (req.postLogoutRedirectUri)
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				if (req.state) url.searchParams.set("state", req.state);
				return { url, method: "GET" };
			}
			const base = req.postLogoutRedirectUri ?? `${GITHUB_ISSUER}/logout`;
			let url: URL;
			try {
				url = new URL(base);
			} catch {
				throw new Error(
					`GitHub federation "${config.name}" received an invalid postLogoutRedirectUri: ${base}`,
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
			return claims as MappedClaims;
		},
	};
}

/**
 * Const Module for the GitHub federation integration.
 *
 * Contributes both `federations.github` (FederationProvider — upstream OAuth 2
 * protocol) and `federationRedirectPolicies.github` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `githubFederationConfig` ComponentMap slot
 * (per A5 §10.2 const-Module pattern).
 *
 * Per A5 §10.2.
 */
export const githubFederationModule = defineModule({
	name: "federation:github",
	requires: ["githubFederationConfig"] as const,
	contributes: {
		federations: {
			// const-module path is single-tenant: see google.mts for the full
			// rationale. provider.name forced to the contribution key "github"
			// regardless of config.name. Multi-tenant consumers use a factory
			// wrap per A5 §10.1 + A2-α §7.1.
			github: (deps) => ({
				...createGithubProvider(deps.githubFederationConfig),
				name: "github",
			}),
		},
		federationRedirectPolicies: {
			github: (deps) => createDefaultFederationRedirectPolicy(deps.githubFederationConfig),
		},
	},
});
